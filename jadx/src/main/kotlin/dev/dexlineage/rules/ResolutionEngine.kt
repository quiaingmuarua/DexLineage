package dev.dexlineage.rules

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import dev.dexlineage.apk.ApkReader
import dev.dexlineage.rules.facts.DexFactSession
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

/** Executes immutable rule revisions over the whole APK; it never receives a desired owner. */
object ResolutionEngine {
    private val implementationId: String by lazy {
        fingerprintArtifacts(mapOf(
            "knowledge" to classArtifact(RuleProofs::class.java),
            "jadx" to classArtifact(ResolutionEngine::class.java),
        ))
    }

    fun buildId(): String = implementationId

    fun execute(artifact: Artifact, rules: List<RuleRevision>, workDir: Path): ResolutionBatch = execute(artifact, rules, workDir, emptyMap())

    fun execute(artifact: Artifact, rules: List<RuleRevision>, workDir: Path, anchors: Map<String, SupportAnchor>): ResolutionBatch {
        val revisions = normalizedRules(rules)
        val engineBuildId = buildId()
        val waiting = revisions.mapNotNull { rule -> rule.requires.values.filter { it !in anchors }.distinct().sorted().takeIf { it.isNotEmpty() }?.let { rule.revisionId to it } }.toMap()
        val ready = revisions.filter { it.revisionId !in waiting }
        val dependencies = ready.associate { it.revisionId to StrategyRegistry.checkDependencies(it, artifact, anchors) }
        if (ready.all { it.strategyId == "builtin.locators" }) {
            val query = RuleEngine.query(artifact, ready.flatMap { it.locators }, workDir)
            return ResolutionBatch(resolveQuery(artifact, ready, engineBuildId, query), query.scan, query.analysis, waiting)
        }
        val builtin = ready.filter { it.strategyId == "builtin.locators" }
        val custom = ready.filter { it.strategyId != "builtin.locators" }
        val results = linkedMapOf<String, StrategyResult>()
        lateinit var builtinQuery: QueryResult
        DexFactSession(artifact, ready.flatMap { StrategyRegistry.literals(it) }.toSet(), dependencies.values.flatMap { it.values }.mapNotNull { it.binding.method }.toSet()).use { session ->
            dependencies.values.flatMap { it.values }.distinctBy { it.key }.forEach { anchor ->
                requireInput(session.classes[anchor.binding.owner.descriptor]?.ref == anchor.binding.owner, "Anchor class/DEX identity absent from APK")
                anchor.binding.method?.let { requireInput(session.method(it) != null, "Anchor method absent from APK") }
            }
            builtinQuery = RuleEngine.queryWithScan(artifact, builtin.flatMap { it.locators }, workDir, session.scan)
            custom.forEach { rule -> results[rule.revisionId] = StrategyRegistry.execute(session, rule, dependencies.getValue(rule.revisionId)) }
        }
        val resolutions = resolveQuery(artifact, builtin, engineBuildId, builtinQuery).toMutableMap()
        custom.forEach { rule ->
            val result = results.getValue(rule.revisionId)
            resolutions[rule.revisionId] = RuleProofs.create(artifact.sha256, rule, engineBuildId, result.matches,
                dependencies.getValue(rule.revisionId), result.unresolvedPaths).also(RuleProofs::validate)
        }
        val already = builtinQuery.analysis?.code.orEmpty()
        val evidenceOwners = custom.filterNot(StrategyRegistry::deferredEvidence).flatMap { results.getValue(it.revisionId).matches }
            .filter { it.status != MatchStatus.FAIL }.flatMap { listOf(it.owner) + it.relatedRefs + it.trace.map { trace -> trace.owner } }.map { it.descriptor }.toSet()
        val extra = ApkReader.decompile(Path.of(artifact.path), evidenceOwners - already.map { it.descriptor }.toSet(), workDir.resolve("strategy-evidence"))
        val analysis = FieldAnalysis(builtinQuery.analysis?.bindings.orEmpty(), (already + extra).distinctBy { it.descriptor },
            builtinQuery.analysis?.diagnostics.orEmpty(), (builtinQuery.analysis?.elapsedMillis ?: 0) + extra.sumOf { it.elapsedMillis }, builtinQuery.analysis?.unavailableOwners.orEmpty())
        Digests.verify(artifact)
        val rpcCalls = results.values.flatMap { it.rpcCalls.orEmpty() }.distinct().sortedWith(compareBy(
            { EntityRef(it.source.owner, it.source).identity }, { it.codeUnitOffset }))
        return ResolutionBatch(resolutions.toSortedMap(), builtinQuery.scan, analysis, waiting, rpcCalls.takeIf { it.isNotEmpty() })
    }

    internal fun normalizedRules(rules: List<RuleRevision>): List<RuleRevision> {
        rules.forEach { rule ->
            RuleProofs.validate(rule)
            StrategyRegistry.validate(rule)
        }
        return rules.distinctBy { it.revisionId }.sortedBy { it.revisionId }
    }

    internal fun resolveQuery(artifact: Artifact, revisions: List<RuleRevision>, engineBuildId: String,
                              query: QueryResult): Map<String, Resolution> {
        if (query.scan.stats.diagnostics.isNotEmpty()) {
            throw ExecutionException("DEX scan incomplete: ${query.scan.stats.diagnostics.joinToString("; ")}")
        }
        val count = revisions.sumOf { it.locators.size }
        requireInput(query.matches.all { it.locatorIndex in 0 until count }, "Query contains an unknown locator index")
        var start = 0
        return revisions.associateTo(linkedMapOf()) { rule ->
            val rangeStart = start
            start += rule.locators.size
            val facts = query.matches.filter { it.locatorIndex in rangeStart until start }
                .map { it.copy(locatorIndex = it.locatorIndex - rangeStart) }
            val resolution = RuleProofs.create(artifact.sha256, rule, engineBuildId, facts)
            RuleProofs.validate(resolution)
            rule.revisionId to resolution
        }
    }

    private fun classArtifact(type: Class<*>): Path = try {
        Path.of(type.protectionDomain.codeSource.location.toURI())
    } catch (e: Exception) {
        throw ExecutionException("Cannot identify matching engine implementation for ${type.name}", e)
    }

    /** Hash class contents, not ZIP timestamps, absolute locations, or hand-written version labels. */
    internal fun fingerprintArtifacts(artifacts: Map<String, Path>): String {
        requireInput(artifacts.isNotEmpty(), "Missing matching implementation artifacts")
        val content = buildString {
            append("dexlineage-matching-build-v1\n")
            append("jadx-version=").append(JADX_VERSION).append('\n')
            for ((name, path) in artifacts.toSortedMap()) {
                append("module=").append(name).append('\n')
                val classes = if (Files.isDirectory(path)) {
                    Files.walk(path).use { files ->
                        files.filter { Files.isRegularFile(it) }.map { file ->
                            path.relativize(file).toString().replace('\\', '/') to file
                        }.filter { (relative, _) -> ownClass(relative) }
                            .toList().associate { (relative, file) -> relative to Digests.file(file) }
                    }
                } else {
                    if (!Files.isRegularFile(path)) throw ExecutionException("Matching implementation artifact missing: $path")
                    ZipFile(path.toFile()).use { zip ->
                        zip.entries().asSequence().filter { !it.isDirectory && ownClass(it.name) }
                            .associate { entry -> entry.name to zip.getInputStream(entry).use { Digests.bytes(it.readAllBytes()) } }
                    }
                }
                if (classes.isEmpty()) throw ExecutionException("Matching implementation has no project classes: $path")
                for ((relative, hash) in classes.toSortedMap()) append(relative).append('\t').append(hash).append('\n')
            }
        }
        return Digests.text(content)
    }

    private fun ownClass(path: String): Boolean = path.startsWith("dev/dexlineage/") && path.endsWith(".class")
}
