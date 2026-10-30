package dev.dexlineage.analysis

import dev.dexlineage.apk.ApkReader
import dev.dexlineage.apk.ApkResearchReader
import dev.dexlineage.apk.ResearchClassFacts
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.EvidenceFiles
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import java.nio.file.Path

data class ResearchTarget(val target: ManualTarget, val annotations: List<ManualAnnotation>,
    val facts: ResearchClassFacts, val evidence: EvidenceRecord)
data class AnalysisResearch(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-research",
    val researchId: String, val corpusFile: Artifact, val corpusId: String, val apk: Artifact,
    val engineBuildId: String, val toolVersion: String = TOOL_VERSION, val jadxVersion: String = JADX_VERSION,
    val stringScope: String = "method-const-string", val callScope: String = "direct-method-reference-invocations",
    val targets: List<ResearchTarget>, val scan: ScanStats, val counts: Map<String, Int>,
    val factsMillis: Long, val decompileMillis: Long, val elapsedMillis: Long)
data class AnalysisResearchResult(val schemaVersion: Int = SCHEMA_VERSION, val researchId: String, val corpusId: String,
    val targetCount: Int, val researchPath: String, val evidencePaths: List<String>, val counts: Map<String, Int>)

/** Reads manual source targets before rule authoring; never creates a run, Resolution or Review. */
object ResearchService {
    fun research(corpusPath: Path, targetIds: List<String>, out: Path): AnalysisResearchResult {
        val started = System.nanoTime()
        val corpusFile = Digests.artifact(corpusPath)
        val corpus = ManualCorpusFiles.read(corpusPath)
        val selected = selectTargets(corpus, targetIds)
        val buildId = ResolutionEngine.buildId()
        val researchId = identity(corpusFile, corpus, selected, buildId)
        createNewDirectory(out)
        try {
            val raw = ApkResearchReader.read(corpus.apk, selected.map { it.source })
            val decompileStarted = System.nanoTime()
            val code = ApkReader.decompile(Path.of(corpus.apk.path), selected.map { it.source.descriptor }.toSet(), out.resolve("work"))
            val decompileMillis = (System.nanoTime() - decompileStarted) / 1_000_000
            // Like discovery, research uses a distinct evidence namespace, not a synthetic AnalysisRun.
            val evidence = EvidenceFiles.publish(out, researchId, corpus.apk, selected.map { it.source }, code)
            val targets = attachTargets(corpus, selected, raw.classes, evidence)
            val methods = targets.flatMap { it.facts.methods }
            val counts = sortedMapOf("classes" to targets.size,
                "fields" to targets.sumOf { it.facts.fields.size }, "methods" to methods.size,
                "methodsWithCode" to methods.count { it.hasCode }, "stringUses" to methods.sumOf { it.strings.size },
                "directCalls" to methods.sumOf { it.calls.size }, "fieldAccesses" to methods.sumOf { it.fieldAccesses.size },
                "annotations" to targets.sumOf { it.annotations.size }, "incompleteClasses" to evidence.count { it.incomplete },
                "factDiagnostics" to methods.sumOf { it.diagnostics.size })
            listOf(corpusFile, corpus.apk, corpus.project).forEach(Digests::verify)
            val document = AnalysisResearch(researchId = researchId, corpusFile = corpusFile, corpusId = corpus.corpusId,
                apk = corpus.apk, engineBuildId = buildId, targets = targets, scan = raw.scan, counts = counts,
                factsMillis = raw.elapsedMillis, decompileMillis = decompileMillis, elapsedMillis = (System.nanoTime() - started) / 1_000_000)
            val path = out.resolve("research.json")
            JsonFiles.writeNew(path, document)
            return AnalysisResearchResult(researchId = researchId, corpusId = corpus.corpusId, targetCount = targets.size,
                researchPath = path.toAbsolutePath().toString(), evidencePaths = evidence.flatMap {
                    listOfNotNull(it.javaPath, it.smaliPath).map { relative -> out.resolve(relative).toAbsolutePath().toString() }
                }, counts = counts)
        } catch (e: Exception) {
            JsonFiles.writeNew(out.resolve("failure.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "operation" to "analysis.research",
                "researchId" to researchId, "error" to if (e is ValidationException) "validation" else "execution",
                "message" to (e.message ?: e.javaClass.name)))
            throw e
        }
    }

    internal fun selectTargets(corpus: ManualCorpus, ids: List<String>): List<ManualTarget> {
        requireInput(ids.isNotEmpty() && ids.none(String::isBlank) && ids.distinct().size == ids.size, "Expected nonempty distinct corpus target IDs")
        val byId = corpus.targets.associateBy { it.targetId }
        return ids.sorted().map { id -> byId[id] ?: throw ValidationException("Unknown corpus target: $id") }
    }

    internal fun identity(corpusFile: Artifact, corpus: ManualCorpus, selected: List<ManualTarget>, buildId: String): String =
        Digests.text(JsonFiles.encode(mapOf("kind" to "analysis-research", "schemaVersion" to SCHEMA_VERSION,
            "corpusFile" to corpusFile, "corpusId" to corpus.corpusId, "apk" to corpus.apk,
            "targets" to selected.map { it.targetId }.sorted(), "engineBuildId" to buildId,
            "toolVersion" to TOOL_VERSION, "jadxVersion" to JADX_VERSION)))

    internal fun attachTargets(corpus: ManualCorpus, selected: List<ManualTarget>, facts: List<ResearchClassFacts>,
                               evidence: List<EvidenceRecord>): List<ResearchTarget> {
        requireInput(facts.map { it.ref }.toSet() == selected.map { it.source }.toSet() && facts.size == selected.size,
            "Research facts differ from selected corpus entities")
        requireInput(evidence.map { it.ref }.toSet() == selected.map { it.source }.toSet() && evidence.size == selected.size,
            "Research code evidence differs from selected corpus entities")
        return selected.map { target -> ResearchTarget(target, corpus.annotations.filter { it.ownerDescriptor == target.source.descriptor },
            facts.single { it.ref == target.source }, evidence.single { it.ref == target.source }) }
    }
}
