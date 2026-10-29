package dev.dexlineage.rules

import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import java.nio.file.Path

/** Executes data predicates over one bound initializer. Naming and acceptance belong to scenarios. */
object RuleEngine {
    private val flagBits = mapOf("PUBLIC" to 0x1, "PRIVATE" to 0x2, "PROTECTED" to 0x4, "STATIC" to 0x8,
        "FINAL" to 0x10, "VOLATILE" to 0x40, "TRANSIENT" to 0x80, "SYNTHETIC" to 0x1000, "ENUM" to 0x4000)
    private val visibilities = setOf("PUBLIC", "PRIVATE", "PROTECTED", "PACKAGE")
    private val invocationKinds = setOf("STATIC", "VIRTUAL", "INTERFACE", "DIRECT", "SUPER")

    fun validate(locator: Locator): Unit = checkedInput("locator") {
        requireInput(locator.kind in setOf("string-use", "field-initializer"), "Unsupported locator kind: ${locator.kind}")
        requireInput(locator.anchor.isNotBlank(), "Locator anchor must not be blank")
        if (locator.kind == "string-use") {
            requireInput(locator.factors.isEmpty() && locator.captures.isEmpty(), "string-use does not accept initializer factors or captures")
        } else {
            validateFactors(locator.factors, false)
            validateCaptures(locator.captures)
        }
    }

    fun validate(template: LocatorTemplate): Unit = checkedInput("locator template") {
        requireInput(template.kind in setOf("string-use", "field-initializer"), "Unsupported locator template kind: ${template.kind}")
        requireInput(template.anchorFromCapture.isNotBlank(), "Locator template needs anchorFromCapture")
        if (template.kind == "string-use") {
            requireInput(template.factors.isEmpty() && template.captures.isEmpty(), "string-use template does not accept initializer factors or captures")
        } else {
            validateFactors(template.factors, true)
            validateCaptures(template.captures)
        }
    }

    fun instantiate(template: LocatorTemplate, captures: Map<String, String>): Locator {
        validate(template)
        val anchor = captures[template.anchorFromCapture]
            ?: throw ValidationException("Missing anchor capture: ${template.anchorFromCapture}")
        val factors = template.factors.map { factor ->
            val captureName = factor.valueFromCapture
            if (captureName == null) factor else factor.copy(
                value = captures[captureName] ?: throw ValidationException("Missing factor capture: $captureName"),
                valueFromCapture = null,
            )
        }
        return Locator(template.kind, anchor, factors, template.captures).also(::validate)
    }

    fun evaluate(binding: FieldBinding, locator: Locator): MatchFact {
        validate(locator)
        requireInput(locator.kind == "field-initializer", "FieldBinding requires field-initializer locator")
        val results = mutableListOf<FactorResult>()
        val call = binding.call
        val anchorStatus = when {
            call == null -> if (binding.unknownReason != null) MatchStatus.UNKNOWN else MatchStatus.FAIL
            locator.anchor in call.arguments -> MatchStatus.PASS
            call.arguments.indices.any { call.arguments[it] == null && it !in call.knownNonStringArguments } -> MatchStatus.UNKNOWN
            else -> MatchStatus.FAIL
        }
        results += FactorResult("anchor", anchorStatus, when (anchorStatus) {
            MatchStatus.PASS -> "Anchor is an argument of this field initializer call"
            MatchStatus.FAIL -> "Anchor is not an argument of this field initializer call"
            MatchStatus.UNKNOWN -> binding.unknownReason ?: "One or more call arguments are not resolved string constants"
        })
        locator.factors.forEach { results += evaluateFactor(binding, it) }
        val captures = sortedMapOf<String, String>()
        for (capture in locator.captures) {
            val value = call?.arguments?.getOrNull(capture.argumentIndex)
            if (value == null) {
                val status = if (call != null && (capture.argumentIndex >= call.arguments.size || capture.argumentIndex in call.knownNonStringArguments)) MatchStatus.FAIL else MatchStatus.UNKNOWN
                results += FactorResult("capture:${capture.name}", status, "Argument ${capture.argumentIndex} is not an available string constant")
            } else {
                captures[capture.name] = value
                results += FactorResult("capture:${capture.name}", MatchStatus.PASS, "Captured initializer argument ${capture.argumentIndex}")
            }
        }
        val status = when {
            results.any { it.status == MatchStatus.FAIL } -> MatchStatus.FAIL
            results.any { it.status == MatchStatus.UNKNOWN } -> MatchStatus.UNKNOWN
            else -> MatchStatus.PASS
        }
        return MatchFact(binding.owner, status, results, captures, field = binding)
    }

    fun query(artifact: Artifact, locators: List<Locator>, workDir: Path): QueryResult {
        return queryWithScan(artifact, locators, workDir, ApkReader.scan(Path.of(artifact.path), locators.map { it.anchor }.toSet()))
    }

    internal fun queryWithScan(artifact: Artifact, locators: List<Locator>, workDir: Path, scan: ScanResult): QueryResult {
        locators.forEach(::validate)
        Digests.verify(artifact)
        if (scan.stats.diagnostics.isNotEmpty()) throw ExecutionException("DEX scan incomplete: ${scan.stats.diagnostics.joinToString("; ")}")
        val ownersByLocator = locators.map { locator -> scan.uses[locator.anchor].orEmpty().map { it.classDescriptor }.toSet() }
        val structuralOwners = locators.indices.filter { locators[it].kind == "field-initializer" }
            .flatMap { ownersByLocator[it] }.toSet()
        val analysis = if (locators.any { it.kind == "field-initializer" }) {
            FieldFactsReader.read(artifact, structuralOwners, scan.classes, workDir) { binding ->
                locators.indices.any { i -> locators[i].kind == "field-initializer" && binding.owner.descriptor in ownersByLocator[i] && evaluate(binding, locators[i]).status == MatchStatus.PASS }
            }
        } else null
        val matches = mutableListOf<MatchFact>()
        locators.forEachIndexed { index, locator ->
            if (locator.kind == "string-use") {
                scan.uses[locator.anchor].orEmpty().groupBy { it.classDescriptor }.toSortedMap().forEach { (owner, uses) ->
                    matches += MatchFact(ClassRef(artifact.sha256, owner, scan.classes.getValue(owner)), MatchStatus.PASS,
                        listOf(FactorResult("anchor", MatchStatus.PASS, "Exact method string use")), mapOf("literal" to locator.anchor), stringUses = uses, locatorIndex = index)
                }
            } else {
                ownersByLocator[index].sorted().forEach { owner ->
                    val bindings = analysis!!.bindings.filter { it.owner.descriptor == owner }
                    val ownerUses = scan.uses[locator.anchor].orEmpty().filter { it.classDescriptor == owner }
                    if (bindings.isEmpty()) {
                        matches += missingBindings(ClassRef(artifact.sha256, owner, scan.classes.getValue(owner)), owner in analysis.unavailableOwners, index).copy(stringUses = ownerUses)
                    } else {
                        bindings.forEach { binding ->
                            // Raw locations document the initializer's anchor uses. Field/call association
                            // remains the structural binding, never a same-class string coincidence.
                            matches += evaluate(binding, locator).copy(locatorIndex = index,
                                stringUses = initializerUses(binding, ownerUses))
                        }
                        if (owner in analysis.unavailableOwners) matches += missingBindings(ClassRef(artifact.sha256, owner, scan.classes.getValue(owner)), true, index).copy(stringUses = ownerUses)
                    }
                }
            }
        }
        Digests.verify(artifact)
        return QueryResult(matches.sortedWith(compareBy({ it.locatorIndex }, { it.owner.descriptor }, { it.field?.fieldName.orEmpty() }, { it.field?.fieldType.orEmpty() })), scan, analysis)
    }

    internal fun missingBindings(owner: ClassRef, unknown: Boolean, locatorIndex: Int): MatchFact {
        val status = if (unknown) MatchStatus.UNKNOWN else MatchStatus.FAIL
        val detail = if (unknown) "Original class/field metadata could not be completely read" else "Original class has no fields"
        return MatchFact(owner, status, listOf(FactorResult("target", status, detail)), emptyMap(), locatorIndex = locatorIndex)
    }

    internal fun initializerUses(binding: FieldBinding, uses: List<StringUseSite>): List<StringUseSite> =
        uses.filter { it.classDescriptor == binding.owner.descriptor && it.dexEntry == binding.owner.dexEntry &&
            (binding.initializerMethod == null || it.methodDescriptor == binding.initializerMethod) }

    private fun validateCaptures(captures: List<CaptureSpec>) {
        requireInput(captures.map { it.name }.distinct().size == captures.size, "Duplicate capture names")
        captures.forEach {
            requireInput(it.name.matches(Regex("[A-Za-z][A-Za-z0-9_-]*")), "Invalid capture name: ${it.name}")
            requireInput(it.argumentIndex >= 0, "Negative capture argument index")
        }
    }

    private fun validateFactors(factors: List<FactorSpec>, template: Boolean) {
        factors.forEach { f ->
            val captureName = f.valueFromCapture
            requireInput(captureName == null || template, "Unresolved valueFromCapture in executable locator")
            requireInput(f.value == null || captureName == null, "Use value or valueFromCapture, not both")
            requireInput(captureName == null || captureName.isNotBlank(), "Empty capture reference")
            when (f.kind) {
                "field-flags" -> {
                    requireInput(f.requiredFlags.isNotEmpty() || f.visibility != null, "field-flags needs requiredFlags or visibility")
                    requireInput(f.requiredFlags.all { it in flagBits }, "Unsupported field flag")
                    requireInput(f.visibility == null || f.visibility in visibilities, "Unsupported visibility")
                    requireInput(f.invocationKind == null && f.parameterTypes == null && f.returnType == null && !f.returnSameAsField && f.index == null && f.value == null && f.valueFromCapture == null, "Unexpected field-flags parameters")
                }
                "invocation-kind" -> {
                    requireInput(f.invocationKind in invocationKinds, "Unsupported invocation kind: ${f.invocationKind}")
                    requireInput(f.requiredFlags.isEmpty() && f.visibility == null && f.parameterTypes == null && f.returnType == null && !f.returnSameAsField && f.index == null && f.value == null && f.valueFromCapture == null, "Unexpected invocation-kind parameters")
                }
                "method-signature" -> {
                    requireInput(f.parameterTypes != null || f.returnType != null || f.returnSameAsField, "method-signature needs a constraint")
                    f.parameterTypes?.forEach { requireType(it, false) }
                    f.returnType?.let { requireType(it, true) }
                    requireInput(f.requiredFlags.isEmpty() && f.visibility == null && f.invocationKind == null && f.index == null && f.value == null && f.valueFromCapture == null, "Unexpected method-signature parameters")
                }
                "argument-string" -> {
                    val index = f.index
                    requireInput(index != null && index >= 0, "argument-string needs a non-negative index")
                    requireInput(f.requiredFlags.isEmpty() && f.visibility == null && f.invocationKind == null && f.parameterTypes == null && f.returnType == null && !f.returnSameAsField, "Unexpected argument-string parameters")
                }
                "assignment-owner" -> requireInput(f.requiredFlags.isEmpty() && f.visibility == null && f.invocationKind == null && f.parameterTypes == null && f.returnType == null && !f.returnSameAsField && f.index == null && f.value == null && f.valueFromCapture == null, "Unexpected assignment-owner parameters")
                else -> throw ValidationException("Unsupported factor kind: ${f.kind}")
            }
        }
    }

    private fun requireType(type: String, allowVoid: Boolean) {
        requireInput(type.isNotBlank(), "Empty type descriptor")
        val base = type.dropWhile { it == '[' }
        requireInput(base.isNotEmpty() && (base in listOf("Z", "B", "C", "S", "I", "J", "F", "D") || (allowVoid && type == "V") || (base.startsWith("L") && base.endsWith(";") && base.length > 2 && base.none { it == '.' || it.isWhitespace() })), "Expected DEX type descriptor: $type")
    }

    private fun evaluateFactor(binding: FieldBinding, f: FactorSpec): FactorResult {
        fun result(ok: Boolean, detail: String) = FactorResult(f.kind, if (ok) MatchStatus.PASS else MatchStatus.FAIL, detail)
        fun unknown(detail: String) = FactorResult(f.kind, MatchStatus.UNKNOWN, detail)
        val call = binding.call
        val unknownReason = binding.unknownReason
        if (f.kind == "field-flags") {
            if (binding.accessFlags < 0) return unknown("Original DEX access flags unavailable")
            val mask = f.requiredFlags.fold(0) { bits, flag -> bits or flagBits.getValue(flag) }
            val visibility = when {
                binding.accessFlags and 1 != 0 -> "PUBLIC"
                binding.accessFlags and 2 != 0 -> "PRIVATE"
                binding.accessFlags and 4 != 0 -> "PROTECTED"
                else -> "PACKAGE"
            }
            return result(binding.accessFlags and mask == mask && (f.visibility == null || f.visibility == visibility), "Original field flags=0x${binding.accessFlags.toString(16)}, visibility=$visibility")
        }
        if (f.kind == "assignment-owner") {
            if (binding.assignmentOwner == null) return if (unknownReason != null) unknown(unknownReason) else result(false, "No initializer assignment")
            return result(binding.assignmentOwner == binding.owner.descriptor, "Initializer assignment owner=${binding.assignmentOwner}")
        }
        if (call == null) return if (unknownReason != null) unknown(unknownReason) else result(false, "Initializer is not a method invocation")
        return when (f.kind) {
            "invocation-kind" -> result(call.invocationKind == f.invocationKind, "Invocation kind=${call.invocationKind}")
            "method-signature" -> result(
                (f.parameterTypes == null || f.parameterTypes == call.parameterTypes) &&
                    (f.returnType == null || f.returnType == call.returnType) &&
                    (!f.returnSameAsField || call.returnType == binding.fieldType),
                "Parameters=${call.parameterTypes}; return=${call.returnType}; field=${binding.fieldType}",
            )
            "argument-string" -> {
                val index = f.index!!
                if (index >= call.arguments.size) result(false, "Argument $index does not exist")
                else if (index in call.knownNonStringArguments) result(false, "Argument $index is a known non-string constant")
                else call.arguments[index]?.let { result(f.value == null || it == f.value, "Argument $index is a string constant") }
                    ?: unknown("Argument $index is not a resolved string constant")
            }
            else -> throw ValidationException("Unsupported factor kind: ${f.kind}")
        }
    }
}
