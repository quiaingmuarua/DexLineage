package dev.dexlineage.rules

import com.google.gson.JsonObject
import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.DexFactSession
import dev.dexlineage.rules.recipes.MessagesRecipes
import java.nio.file.Path

/** Compile-time registry. A strategy is executable matching code, never a publication authority. */
object StrategyRegistry {
    private val schemas = mapOf(
        "builtin.method-signature" to setOf("parameterTypes", "returnType", "returnSameAsOwner", "requiredFlags"),
        "messages.logger-fields" to setOf("tag", "component", "captureIndex", "requiredFlags"),
        "messages.handler-name-method" to setOf("logLiteral", "argumentIndex"),
        "messages.named-handler" to setOf("component"),
        "messages.rpc-descriptor" to setOf("service", "rpc", "requestLabel", "responseLabel", "nameLabel"),
        "messages.rpc-message" to setOf("service", "rpc", "role", "requestLabel", "responseLabel", "nameLabel"),
    )
    private val roles = mapOf("builtin.method-signature" to mapOf("owner" to EntityKind.CLASS),
        "messages.logger-fields" to mapOf("factory" to EntityKind.METHOD),
        "messages.handler-name-method" to mapOf("lifecycle" to EntityKind.CLASS),
        "messages.named-handler" to mapOf("nameMethod" to EntityKind.METHOD),
        "messages.rpc-descriptor" to emptyMap(), "messages.rpc-message" to mapOf("descriptor" to EntityKind.METHOD))

    fun dependencyKinds(rule: RuleRevision): Map<String, EntityKind> {
        validate(rule)
        return if (rule.strategyId == "builtin.locators") emptyMap() else roles.getValue(rule.strategyId)
    }

    fun validate(rule: RuleRevision) = checkedInput("matching strategy") {
        RuleProofs.validate(rule)
        if (rule.strategyId == "builtin.locators") {
            requireInput(rule.resultKind == EntityKind.CLASS && rule.requires.isEmpty() && rule.parameters.size() == 0, "Builtin locators have CLASS results and no dependencies/parameters")
            rule.locators.forEach(RuleEngine::validate)
        } else {
            val keys = schemas[rule.strategyId] ?: throw ValidationException("Unknown strategy: ${rule.strategyId}")
            requireInput(rule.locators.isEmpty() && rule.parameters.keySet().all { it in keys }, "Unsupported strategy parameters/locators: ${rule.strategyId}")
            requireInput(rule.requires.keys == roles.getValue(rule.strategyId).keys, "Strategy requires roles ${roles.getValue(rule.strategyId).keys}")
            val expected = if (rule.strategyId in setOf("builtin.method-signature", "messages.handler-name-method", "messages.rpc-descriptor")) EntityKind.METHOD else EntityKind.CLASS
            requireInput(rule.resultKind == expected, "${rule.strategyId} returns $expected")
            rule.parameters.entrySet().forEach { (key, value) ->
                when (key) {
                    "parameterTypes", "requiredFlags" -> requireInput(value.isJsonArray && value.asJsonArray.all { it.isJsonPrimitive && it.asJsonPrimitive.isString }, "Expected string array: $key")
                    "returnSameAsOwner" -> requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isBoolean, "Expected boolean: $key")
                    "argumentIndex", "captureIndex" -> requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isNumber && value.asString.toIntOrNull()?.let { it >= 0 } == true, "Expected nonnegative integer: $key")
                    else -> requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isString && value.asString.isNotBlank(), "Expected nonempty string: $key")
                }
            }
            if (rule.strategyId == "builtin.method-signature") requireInput(rule.parameters.has("parameterTypes"), "Method signature needs parameterTypes")
            rule.parameters.array("parameterTypes").orEmpty().forEach { requireInput(typeDescriptor(it, false), "Invalid parameter type: $it") }
            rule.parameters.string("returnType")?.let { requireInput(typeDescriptor(it, true), "Invalid return type: $it") }
            if (rule.strategyId == "messages.handler-name-method") requireInput(rule.parameters.has("logLiteral"), "Missing logLiteral")
            if (rule.strategyId.startsWith("messages.rpc-")) requireInput(rule.parameters.has("service") && rule.parameters.has("rpc"), "RPC strategies require service and rpc")
            if (rule.strategyId == "messages.rpc-message") requireInput(rule.parameters.string("role") in setOf("request", "response"), "RPC message role must be request or response")
            rule.parameters.array("requiredFlags")?.forEach { requireInput(it in flags, "Unknown access flag: $it") }
        }
    }

    internal fun checkDependencies(rule: RuleRevision, artifact: Artifact, anchors: Map<String, SupportAnchor>): Map<String, SupportAnchor> {
        val resolved = rule.requires.mapValues { (_, key) -> anchors.getValue(key) }
        resolved.forEach { (role, anchor) ->
            RuleProofs.validateAnchor(anchor)
            requireInput(anchor.key == rule.requires.getValue(role), "Dependency key mismatch")
            requireInput(anchor.binding.owner.apkSha256 == artifact.sha256, "Dependency belongs to another APK")
            requireInput(anchor.binding.kind == roles.getValue(rule.strategyId).getValue(role), "Dependency $role has wrong entity kind")
        }
        return resolved
    }

    internal fun literals(rule: RuleRevision): Set<String> = if (rule.strategyId == "builtin.locators") rule.locators.map { it.anchor }.toSet()
        else listOf("tag", "component", "logLiteral", "service", "rpc").mapNotNull { rule.parameters.string(it) }.toSet()

    internal fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): List<MatchFact> =
        MessagesRecipes.execute(session, rule, dependencies)

    fun discover(artifact: Artifact, rule: RuleRevision, workDir: Path, anchors: Map<String, SupportAnchor> = emptyMap()): QueryResult {
        validate(rule)
        requireInput(rule.requires.values.all { it in anchors }, "Discovery dependencies are not resolved")
        if (rule.strategyId == "builtin.locators") return RuleEngine.query(artifact, rule.locators, workDir)
        val dependencies = checkDependencies(rule, artifact, anchors)
        DexFactSession(artifact, literals(rule), dependencies.values.mapNotNull { it.binding.method }.toSet()).use { session ->
            dependencies.values.forEach { dependency ->
                requireInput(session.classes[dependency.binding.owner.descriptor]?.ref == dependency.binding.owner, "Dependency class/DEX identity absent from APK")
                dependency.binding.method?.let { requireInput(session.method(it) != null, "Dependency method absent from APK") }
            }
            val facts = execute(session, rule, dependencies)
            val owners = facts.filter { it.status != MatchStatus.FAIL }.flatMap { listOf(it.owner) + it.relatedRefs + it.trace.map { trace -> trace.owner } }.map { it.descriptor }.toSet()
            val code = ApkReader.decompile(Path.of(artifact.path), owners, workDir.resolve("evidence"))
            return QueryResult(facts, session.scan, FieldAnalysis(emptyList(), code, emptyList(), code.sumOf { it.elapsedMillis }))
        }
    }

    internal val flags = mapOf("PUBLIC" to 1, "PRIVATE" to 2, "PROTECTED" to 4, "STATIC" to 8, "FINAL" to 16,
        "SYNCHRONIZED" to 32, "BRIDGE" to 64, "NATIVE" to 256, "ABSTRACT" to 1024, "SYNTHETIC" to 4096)
    private fun typeDescriptor(value: String, allowVoid: Boolean): Boolean {
        if (value == "V") return allowVoid
        val element = value.dropWhile { it == '[' }
        if (element.length == 1 && element[0] in "ZBSCIJFD") return true
        return try { Identities.requireDescriptor(element); true } catch (_: ValidationException) { false }
    }
}

internal fun JsonObject.string(key: String): String? = get(key)?.takeUnless { it.isJsonNull }?.asString
internal fun JsonObject.number(key: String, default: Int) = get(key)?.asInt ?: default
internal fun JsonObject.array(key: String): List<String>? = getAsJsonArray(key)?.map { it.asString }
