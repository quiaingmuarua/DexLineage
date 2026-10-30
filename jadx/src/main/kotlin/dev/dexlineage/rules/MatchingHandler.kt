package dev.dexlineage.rules

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.DexFactSession
import dev.dexlineage.knowledge.RuleProofs
import java.nio.file.Files
import java.nio.file.Path

/** A registered compiled matcher has no review or publication authority. */
internal interface MatchingHandler {
    val id: String
    val resultKind: EntityKind
    val dependencyKinds: Map<String, EntityKind>
    val evidenceMode: EvidenceMode get() = EvidenceMode.EAGER
    fun validate(rule: RuleRevision)
    fun validateProducers(rule: RuleRevision, producers: Map<String, RuleRevision>) = Unit
    fun scanNeeds(rule: RuleRevision): ScanNeeds = ScanNeeds()
    fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult
}

internal enum class EvidenceMode { EAGER, ON_INSPECT }
internal data class ScanNeeds(val literals: Set<String> = emptySet())

/** Validation and lookup do not interpret any handler's parameters or producer IDs. */
internal class HandlerRegistry(definitions: List<MatchingHandler>) {
    private val handlers = definitions.associateBy { it.id }
    init { requireInput(this.handlers.size == definitions.size, "Duplicate registered strategy ID") }
    fun handler(id: String): MatchingHandler = handlers[id] ?: throw ValidationException("Unknown strategy: $id")
    fun validate(rule: RuleRevision) = checkedInput("matching strategy") {
        RuleProofs.validate(rule)
        val handler = handler(rule.strategyId)
        requireInput(rule.resultKind == handler.resultKind, "${rule.strategyId} returns ${handler.resultKind}")
        requireInput(rule.requires.keys == handler.dependencyKinds.keys, "Strategy requires roles ${handler.dependencyKinds.keys}")
        handler.validate(rule)
    }
    fun validateDependencyDefinitions(rule: RuleRevision, producers: Map<String, RuleRevision>) {
        validate(rule)
        val handler = handler(rule.strategyId)
        handler.dependencyKinds.forEach { (role, expected) ->
            val key = rule.requires.getValue(role)
            val producer = producers[key] ?: throw ValidationException("Missing dependency definition: $key")
            requireInput(producer.resultKind == expected, "Dependency $role requires $expected")
        }
        handler.validateProducers(rule, producers)
    }
}
internal data class StrategyResult(val matches: List<MatchFact>, val unresolvedPaths: List<MatchUncertainty> = emptyList(),
    val artifacts: List<ProducedArtifact> = emptyList())

/** Concrete payloads retain their Kotlin type; only their deterministic bytes cross the generic writer. */
internal interface ProducedArtifact {
    val kind: String
    fun encode(): String
}

internal data class TypedArtifact<T : Any>(override val kind: String, val value: T) : ProducedArtifact {
    override fun encode(): String = JsonFiles.encode(value)
}

internal object MatchingArtifacts {
    fun write(workDir: Path, artifacts: List<ProducedArtifact>): List<ScenarioArtifactRef> = artifacts.distinct().map { artifact ->
        requireInput(artifact.kind.matches(Regex("[a-z][a-z0-9.-]*")), "Invalid scenario artifact kind")
        val content = artifact.encode()
        val digest = Digests.text(content)
        val path = workDir.resolve("artifacts").resolve("$digest.json").toAbsolutePath()
        Files.createDirectories(path.parent)
        if (Files.exists(path)) requireInput(Digests.file(path) == digest, "Scenario artifact collision")
        else Files.writeString(path, content, java.nio.file.StandardOpenOption.CREATE_NEW)
        ScenarioArtifactRef(artifact.kind, path.toString(), digest)
    }.distinct().sortedWith(compareBy({ it.kind }, { it.sha256 }))
}

/** Structural helpers shared by handler-owned validators; no application vocabulary. */
internal object HandlerInputs {
    fun only(rule: RuleRevision, allowed: Set<String>) {
        requireInput(rule.locators.isEmpty() && rule.parameters.keySet().all { it in allowed }, "Unsupported strategy parameters/locators: ${rule.strategyId}")
    }
    fun strings(rule: RuleRevision, keys: Set<String>) {
        keys.forEach { key -> rule.parameters.get(key)?.let { value ->
            requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isString && value.asString.isNotBlank(), "Expected nonempty string: $key")
        } }
    }
    fun requiredString(rule: RuleRevision, key: String) {
        requireInput(rule.parameters.has(key), "Missing strategy parameter: $key")
        strings(rule, setOf(key))
    }
    fun index(rule: RuleRevision, key: String) {
        rule.parameters.get(key)?.let { value ->
            requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isNumber && value.asString.toIntOrNull()?.let { it >= 0 } == true, "Expected nonnegative integer: $key")
        }
    }
    fun stringArray(rule: RuleRevision, key: String) {
        rule.parameters.get(key)?.let { value ->
            requireInput(value.isJsonArray && value.asJsonArray.all { it.isJsonPrimitive && it.asJsonPrimitive.isString }, "Expected string array: $key")
        }
    }
    fun accessFlags(rule: RuleRevision, key: String = "requiredFlags") {
        stringArray(rule, key)
        rule.parameters.array(key)?.forEach { requireInput(it in flags, "Unknown access flag: $it") }
    }
    val flags = mapOf("PUBLIC" to 1, "PRIVATE" to 2, "PROTECTED" to 4, "STATIC" to 8, "FINAL" to 16,
        "SYNCHRONIZED" to 32, "BRIDGE" to 64, "NATIVE" to 256, "ABSTRACT" to 1024, "SYNTHETIC" to 4096)
    fun descriptor(value: String, allowVoid: Boolean): Boolean {
        if (value == "V") return allowVoid
        val element = value.dropWhile { it == '[' }
        if (element.length == 1 && element[0] in "ZBSCIJFD") return true
        return try { Identities.requireDescriptor(element); true } catch (_: ValidationException) { false }
    }
}
