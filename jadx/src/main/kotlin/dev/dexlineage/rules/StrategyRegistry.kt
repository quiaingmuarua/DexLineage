package dev.dexlineage.rules

import com.google.gson.JsonObject
import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.DexFactSession
import dev.dexlineage.messages.MessagesHandlers
import java.nio.file.Path

/** Compile-time registry. A strategy is executable matching code, never a publication authority. */
object StrategyRegistry {
    private val registered = HandlerRegistry(listOf(LocatorHandler, MethodSignatureHandler) + MessagesHandlers.all)

    internal fun handler(rule: RuleRevision): MatchingHandler = registered.handler(rule.strategyId)
    fun dependencyKinds(rule: RuleRevision): Map<String, EntityKind> {
        validate(rule)
        return handler(rule).dependencyKinds
    }
    fun validate(rule: RuleRevision) = registered.validate(rule)
    fun validateDependencyDefinitions(rule: RuleRevision, producers: Map<String, RuleRevision>) =
        registered.validateDependencyDefinitions(rule, producers)

    internal fun checkDependencies(rule: RuleRevision, artifact: Artifact, anchors: Map<String, SupportAnchor>): Map<String, SupportAnchor> {
        val resolved = rule.requires.mapValues { (_, key) -> anchors.getValue(key) }
        resolved.forEach { (role, anchor) ->
            RuleProofs.validateAnchor(anchor)
            requireInput(anchor.key == rule.requires.getValue(role), "Dependency key mismatch")
            requireInput(anchor.binding.owner.apkSha256 == artifact.sha256, "Dependency belongs to another APK")
            requireInput(anchor.binding.kind == handler(rule).dependencyKinds.getValue(role), "Dependency $role has wrong entity kind")
        }
        validateDependencyDefinitions(rule, resolved.values.associate { it.key to it.rule })
        return resolved
    }

    internal fun literals(rule: RuleRevision): Set<String> = handler(rule).scanNeeds(rule).literals
    internal fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult =
        handler(rule).execute(session, rule, dependencies)
    internal fun deferredEvidence(rule: RuleRevision): Boolean = handler(rule).evidenceMode == EvidenceMode.ON_INSPECT

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
            val result = execute(session, rule, dependencies)
            val facts = result.matches
            val owners = facts.filter { it.status != MatchStatus.FAIL }.flatMap { listOf(it.owner) + it.relatedRefs + it.trace.map { trace -> trace.owner } }.map { it.descriptor }.toSet()
            val code = if (deferredEvidence(rule)) emptyList() else ApkReader.decompile(Path.of(artifact.path), owners, workDir.resolve("evidence"))
            return QueryResult(facts, session.scan, FieldAnalysis(emptyList(), code, emptyList(), code.sumOf { it.elapsedMillis }),
                MatchingArtifacts.write(workDir, result.artifacts), result.unresolvedPaths)
        }
    }


}

internal fun JsonObject.string(key: String): String? = get(key)?.takeUnless { it.isJsonNull }?.asString
internal fun JsonObject.number(key: String, default: Int) = get(key)?.asInt ?: default
internal fun JsonObject.array(key: String): List<String>? = getAsJsonArray(key)?.map { it.asString }
