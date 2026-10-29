package dev.dexlineage.rules

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
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

    fun execute(artifact: Artifact, rules: List<RuleRevision>, workDir: Path): ResolutionBatch {
        val revisions = normalizedRules(rules)
        val engineBuildId = buildId()
        // A single query scans the union of literal anchors, then loads structural owners in a batch.
        // An empty revision list still scans the class inventory and detects incomplete input.
        val query = RuleEngine.query(artifact, revisions.flatMap { it.locators }, workDir)
        val resolutions = resolveQuery(artifact, revisions, engineBuildId, query)
        return ResolutionBatch(resolutions, query.scan, query.analysis)
    }

    internal fun normalizedRules(rules: List<RuleRevision>): List<RuleRevision> {
        rules.forEach { rule ->
            RuleProofs.validate(rule)
            rule.locators.forEach(RuleEngine::validate)
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
