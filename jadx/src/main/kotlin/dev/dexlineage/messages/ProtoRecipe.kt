package dev.dexlineage.messages

import dev.dexlineage.model.*
import dev.dexlineage.rules.*
import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*

/** Messages' observed protobuf-lite metadata relationship, without source or obfuscated names. */
internal object ProtoRecipe {
    private const val OBJECT = "Ljava/lang/Object;"
    private const val STRING = "Ljava/lang/String;"
    private const val ARRAY = "[Ljava/lang/Object;"
    private data class Factory(val method: Method, val constructor: Method)

    fun execute(s: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult {
        val parent = dependencies.getValue("parent").binding.owner
        val catalogue = s.cachedRecipe("messages-proto-fields:${parent.descriptor}") { read(s, parent) }
        val number = rule.parameters.get("fieldNumber")?.asInt
        val cardinality = rule.parameters.string("cardinality")
        val fields = catalogue.fields.filter { it.kind == "message" && (number == null || it.fieldNumber == number) &&
            (cardinality == null || it.cardinality == cardinality) }
        val matches = fields.map { field ->
            val site = catalogue.metadata.first { it.source == field.source && it.codeUnitOffset == field.codeUnitOffset && it.status == "RESOLVED" }
            val detail = "One verified metadata call binds field ${field.fieldNumber} (${field.cardinality}) to ${field.relatedType!!.descriptor}"
            MatchFact(field.relatedType, MatchStatus.PASS, listOf(FactorResult("proto-metadata-field", MatchStatus.PASS, detail)),
                mapOf("fieldNumber" to field.fieldNumber.toString(), "cardinality" to field.cardinality),
                relatedRefs = (listOf(parent) + listOfNotNull(site.factory?.owner, site.metadataConstructor?.owner)).distinct(),
                trace = listOf(FactTrace(field.source.owner, field.source.name + field.source.descriptor, field.codeUnitOffset, "proto-metadata-field", detail)))
        }.distinct()
        val unresolved = catalogue.unresolvedPaths.filter { (it.fieldNumber == null || number == null || it.fieldNumber == number) &&
            (it.cardinality == null || cardinality == null || it.cardinality == cardinality) }.map { it.uncertainty() }
        return StrategyResult(matches, unresolved, listOf(TypedArtifact(MessagesProtoArtifacts.KIND, catalogue)))
    }

    private fun read(s: DexFactSession, parent: ClassRef): ProtoFieldCatalogue {
        val metadata = mutableListOf<ProtoMetadataSite>(); val fields = mutableListOf<ProtoFieldFact>(); val problems = mutableListOf<ProtoPathProblem>()
        val methods = dispatchMethods(s, parent.descriptor)
        if (methods.isEmpty()) {
            val location = s.methods(parent.descriptor).sortedWith(compareBy<Method>({ if (it.id.result == OBJECT && it.id.args.size == 3) 0 else 1 }, { it.id.key })).firstOrNull()
                ?: throw dev.dexlineage.io.ExecutionException("Proto metadata is unavailable and parent ${parent.descriptor} has no method to locate the missing facts")
            problems += ProtoPathProblem(s.methodRef(location.id), null, "No inherited protobuf dispatch override could be verified on the parent")
        }
        for (method in methods) {
            val source = s.methodRef(method.id)
            val potential = MethodCodeFacts.callSites(method).filter { it.isStatic && metadataSignature(s, parent.descriptor, it.method) }.map { it.offset }.toSet()
            if (potential.isEmpty()) {
                problems += ProtoPathProblem(source, null, "Dispatch method contains no readable metadata factory call")
                continue
            }
            val before = metadata.size
            val slices = s.slices(method)
            slices.uncertainties.filter { it.relevantCallOffsets == null || it.relevantCallOffsets.any(potential::contains) }.forEach {
                problems += ProtoPathProblem(source, it.offset, "Metadata dispatch path is unresolved: ${it.reason}")
            }
            for (path in slices.paths.filter { it.complete }) for (call in path.calls.filter { it.offset in potential }) {
                when (returnRelation(path, call)) {
                    MetadataReturn.IGNORED -> continue
                    MetadataReturn.UNKNOWN -> {
                        problems += ProtoPathProblem(source, call.offset, "Opaque dispatch return may forward or replace the metadata result")
                        continue
                    }
                    MetadataReturn.DIRECT -> Unit
                }
                val info = (call.args.getOrNull(1) as? Value.Text)?.value
                val objects = objects(call)
                val default = call.args.firstOrNull() as? Value.FieldRead
                val factory = resolveFactory(s, call.method)
                val issue = when {
                    metadataLifetimeProblem(path, call) != null -> metadataLifetimeProblem(path, call)
                    factory == null -> "Metadata factory declaration or three-argument construction forwarding is unsupported"
                    !ownDefault(s, parent.descriptor, default) -> "Metadata default instance is not verified as the current parent default"
                    info == null -> "Metadata info is not one constant string"
                    objects == null -> "Metadata Object[] is not one complete local array snapshot"
                    else -> null
                }
                val decoded = if (issue == null) ProtoMetadataDecoder.decode(info!!, objects!!, s.fields(parent.descriptor), call.method.args[0],
                    { s.classes[it]?.ref }, s::isSubtype) else null
                val reason = issue ?: decoded?.problem
                metadata += ProtoMetadataSite(source, call.offset, if (reason == null) "RESOLVED" else "UNKNOWN",
                    factory?.let { s.methodRef(it.method.id) }, info, objects.orEmpty(), default?.field?.key,
                    listOfNotNull(reason), factory?.let { s.methodRef(it.constructor.id) })
                if (reason != null) problems += ProtoPathProblem(source, call.offset, reason)
                else decoded!!.fields.forEach { field -> fields += ProtoFieldFact(field.number, field.cardinality, field.kind,
                    field.field.name, field.field.type, field.typeId, field.child, source, call.offset) }
            }
            if (metadata.size == before && problems.none { it.source == source })
                problems += ProtoPathProblem(source, null, "No metadata factory result was reliably returned by the dispatch method")
        }
        return ProtoFieldCatalogue(apkSha256 = s.artifact.sha256, parent = parent,
            metadata = metadata.distinct().sortedWith(compareBy({ it.source.name + it.source.descriptor }, { it.codeUnitOffset }, { it.info.orEmpty() })),
            fields = fields.distinct().sortedWith(compareBy({ it.fieldNumber }, { it.cardinality }, { it.relatedType?.descriptor.orEmpty() }, { it.source.name }, { it.codeUnitOffset })),
            unresolvedPaths = problems.distinct().sortedWith(compareBy({ it.source.name }, { it.codeUnitOffset ?: -1 }, { it.reason })))
            .also(MessagesProtoArtifacts::validate)
    }

    private fun dispatchMethods(s: DexFactSession, owner: String): List<Method> {
        val parent = s.classes[owner]?.parent ?: return emptyList()
        return s.methods(owner).filter { method ->
            val id = method.id
            method.flags and 8 == 0 && id.result == OBJECT && id.args.size == 3 && id.args.drop(1) == listOf(OBJECT, OBJECT) &&
                s.isSubtype(id.args[0], "Ljava/lang/Enum;") &&
                s.inheritedMethod(parent, id.name, id.descriptor)?.let { it.flags and 8 == 0 && it.flags and 0x400 != 0 } == true
        }
    }

    private fun metadataSignature(s: DexFactSession, owner: String, id: MethodId): Boolean =
        id.args.size == 3 && id.args[1] == STRING && id.args[2] == ARRAY && id.result == OBJECT && s.isSubtype(owner, id.args[0])

    private fun sameCall(value: Value, call: CallEvent): Boolean = when (value) {
        is Value.Invocation -> value.site == call.offset && value.method == call.method
        is Value.CallResult -> value.site == call.offset && value.method == call.method
        else -> false
    }

    internal enum class MetadataReturn { DIRECT, IGNORED, UNKNOWN }

    /** An opaque return is not evidence that an earlier metadata call was irrelevant. */
    internal fun returnRelation(path: RawTrace, call: CallEvent): MetadataReturn {
        if (path.returns.isEmpty()) return MetadataReturn.IGNORED // A complete throwing/void path returns no metadata.
        if (path.returns.all { sameCall(it.value, call) }) return MetadataReturn.DIRECT
        if (path.returns.all { it.value is Value.Text || it.value is Value.Number || it.value is Value.ClassLiteral }) return MetadataReturn.IGNORED
        return MetadataReturn.UNKNOWN
    }

    internal fun metadataLifetimeProblem(path: RawTrace, call: CallEvent): String? {
        val array = call.args.getOrNull(2) as? Value.Array ?: return null
        val effect = path.arrayEffects.firstOrNull { it.array == array && call.offset in it.precedingCalls } ?: return null
        return "Metadata Object[] was mutated or escaped after the factory call at ${effect.offset}: ${effect.reason}"
    }

    private fun objects(call: CallEvent): List<ProtoMetadataObject>? {
        val value = call.args.getOrNull(2)
        if (value is Value.Number && value.value == 0L) return emptyList()
        val array = value as? Value.Array ?: return null
        val contents = call.arrays[array] ?: return null
        if (contents.keys.sorted() != (0 until contents.size).toList()) return null
        return contents.toSortedMap().map { (index, item) -> when (item) {
            is Value.Text -> ProtoMetadataObject(index, "STRING", text = item.value)
            is Value.ClassLiteral -> ProtoMetadataObject(index, "CLASS", type = item.type)
            else -> ProtoMetadataObject(index, "UNKNOWN")
        } }
    }

    private fun resolveFactory(s: DexFactSession, id: MethodId): Factory? = s.cachedRecipe("proto-factory:${id.key}") {
        // Cache a nullable result through a non-null container.
        listOf(resolveFactoryUncached(s, id))
    }.single()

    private fun resolveFactoryUncached(s: DexFactSession, id: MethodId): Factory? {
        val method = s.inheritedMethod(id.owner, id.name, id.descriptor) ?: return null
        if (method.flags and 8 == 0 || !MethodCodeFacts.controlShape(method).straightLine) return null
        val trace = s.trace(method)
        if (!trace.complete || trace.returns.size != 1 || trace.calls.size != 1 || trace.writes.isNotEmpty()) return null
        val constructors = trace.returns.map { ret ->
            val allocation = ret.value as? Value.Allocation ?: return null
            val call = trace.constructions[allocation] ?: return null
            if (call.method.name != "<init>" || call.method.owner != allocation.type || call.args != id.args.mapIndexed { index, type -> Value.Parameter(index, type) }) return null
            if (call.method.args.size != id.args.size || call.method.args.zip(id.args).any { (parameter, argument) ->
                parameter != argument && !s.isSubtype(argument, parameter) }) return null
            val constructor = s.method(call.method) ?: return null
            val body = s.trace(constructor)
            if (!body.complete || !constructorConfined(body, allocation.type)) return null
            val writes = body.writes.filter { it.receiver == Value.Parameter(-1, allocation.type) && it.field.owner == allocation.type }
            val stored = constructor.id.args.mapIndexed { index, type -> writes.filter { it.value == Value.Parameter(index, type) &&
                (it.field.type == type || s.isSubtype(type, it.field.type)) } }
            if (stored.any { it.size != 1 } || stored.flatten().map { it.field.key }.distinct().size != 3) return null
            if (stored.flatten().any { initial -> writes.any { it.field.key == initial.field.key && it.value != initial.value } }) return null
            // The convergent trace excludes later overwrites. Path prefixes separately prove that
            // all three stores actually occurred together before any unbounded flags loop.
            val slices = s.slices(constructor)
            if (slices.paths.isEmpty() || slices.uncertainties.any { !it.reason.contains("loop") }) return null
            if (slices.paths.any { path -> stored.flatten().any { expected -> path.writes.none { it.field.key == expected.field.key &&
                it.receiver == expected.receiver && it.value == expected.value } } }) return null
            constructor
        }.distinctBy { it.id }
        return constructors.singleOrNull()?.let { Factory(method, it) }
    }

    /** A constructor's forwarding proof is invalid if an unanalysed callee can mutate its state. */
    internal fun constructorConfined(trace: RawTrace, owner: String): Boolean {
        fun tainted(value: Value): Boolean = when (value) {
            is Value.Parameter -> value.index == -1 || value.index == 2 && value.type == ARRAY
            is Value.FieldRead -> value.receiver?.let(::tainted) == true
            is Value.Invocation -> (value.args + listOfNotNull(value.receiver)).any(::tainted)
            else -> false
        }
        fun reference(type: String) = type.startsWith("L") || type.startsWith("[")
        for (call in trace.calls) {
            val id = call.method
            val intrinsic = id == MethodId("Ljava/lang/Object;", "<init>", emptyList(), "V") && call.receiver == Value.Parameter(-1, owner) ||
                id == MethodId("Ljava/lang/Object;", "getClass", emptyList(), "Ljava/lang/Class;") ||
                id == MethodId(STRING, "charAt", listOf("I"), "C") || id == MethodId(STRING, "length", emptyList(), "I")
            if (intrinsic) continue
            if (call.receiver?.let { tainted(it) || it == Value.Unknown } == true) return false
            if (call.args.withIndex().any { (index, value) -> tainted(value) || value == Value.Unknown && reference(id.args[index]) }) return false
        }
        return trace.writes.none { write ->
            tainted(write.value) && !(write.value == Value.Parameter(2, ARRAY) &&
                write.receiver == Value.Parameter(-1, owner) && write.field.owner == owner && write.field.type == ARRAY)
        }
    }

    private fun ownDefault(s: DexFactSession, owner: String, value: Value.FieldRead?): Boolean {
        if (value == null || value.receiver != null || value.field.owner != owner || value.field.type != owner) return false
        val field = s.fields(owner).singleOrNull { it.key == value.field.key && it.flags and (8 or 16) == (8 or 16) } ?: return false
        val initializer = s.methods(owner).singleOrNull { it.id.name == "<clinit>" } ?: return false
        val slices = s.slices(initializer)
        if (slices.uncertainties.isNotEmpty() || slices.paths.isEmpty()) return false
        return slices.paths.all { trace ->
            val writes = trace.writes.filter { it.field.key == field.key }
            if (writes.isEmpty() || writes.any { it.value !is Value.Allocation || it.value.type != owner }) return@all false
            val allocations = writes.map { it.value }.toSet()
            trace.calls.any { call -> call.receiver == null && call.method.args.size == 2 && call.method.args[0] == "Ljava/lang/Class;" &&
                call.method.result == "V" && call.args[0] == Value.ClassLiteral(owner) &&
                s.isSubtype(owner, call.method.args[1]) && s.inheritedMethod(call.method.owner, call.method.name, call.method.descriptor)?.let { it.flags and 8 != 0 && s.isSubtype(owner, it.id.owner) } == true &&
                (call.args[1] in allocations || (call.args[1] as? Value.FieldRead)?.field?.key == field.key) }
        }
    }
}

internal class ProtoHandler(override val id: String, private val select: Boolean) : MatchingHandler {
    override val resultKind = EntityKind.CLASS
    override val dependencyKinds = mapOf("parent" to EntityKind.CLASS)
    override val evidenceMode = EvidenceMode.ON_INSPECT
    override fun validate(rule: RuleRevision) {
        HandlerInputs.only(rule, if (select) setOf("fieldNumber", "cardinality") else emptySet())
        if (select) {
            val number = rule.parameters.get("fieldNumber")
            dev.dexlineage.io.requireInput(number != null && number.isJsonPrimitive && number.asJsonPrimitive.isNumber &&
                number.asString.toIntOrNull()?.let { it in 1..536870911 } == true, "Proto fieldNumber must be a positive integer")
            HandlerInputs.requiredString(rule, "cardinality")
            dev.dexlineage.io.requireInput(rule.parameters.string("cardinality") in setOf("singular", "repeated"), "Proto cardinality must be singular or repeated")
        }
    }
    override fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>) = ProtoRecipe.execute(session, rule, dependencies)
}
