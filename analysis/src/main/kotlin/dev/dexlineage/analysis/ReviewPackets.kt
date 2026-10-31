package dev.dexlineage.analysis

import com.google.gson.JsonArray
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.EvidenceFiles
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path

data class ReviewPacketEvidence(val evidenceId: String, val ref: ClassRef, val javaFile: Artifact,
    val smaliFile: Artifact?, val incomplete: Boolean, val diagnostics: List<String>)
data class ReviewPacketTask(val task: AnalysisTask, val state: TaskState, val reason: String,
    val latestRevision: String?, val methodDetails: JsonObject, val requiredEvidenceIds: List<String>, val evidenceIds: List<String>)
data class ReviewPacket(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-review-packet",
    val runId: String, val apkSha256: String, val engineBuildId: String, val tasks: List<ReviewPacketTask>,
    val sharedEvidence: List<ReviewPacketEvidence>)
data class ReviewPacketResult(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-review-packet-manifest",
    val runId: String, val taskIds: List<String>, val packetPath: String, val templatePath: String,
    val summaryPath: String, val files: List<Artifact>)

/** Mechanical evidence association only. The template deliberately contains no semantic decision. */
object ReviewPackets {
    fun write(runDir: Path, taskIds: Set<String>, outDir: Path): ReviewPacketResult {
        val run = AnalysisService.readRun(runDir)
        requireInput(taskIds.all { id -> run.tasks.any { it.taskId == id } }, "Unknown review-packet selection")
        createNewDirectory(outDir)
        val records = (if (taskIds.isEmpty()) emptyList() else AnalysisService.inspect(runDir, taskIds)).associateBy { it.ref }
        val views = AnalysisService.tasks(runDir, "ALL", limit = Int.MAX_VALUE).items.associateBy { it.task.taskId }
        val selected = taskIds.sorted().map { id ->
            val task = run.tasks.single { it.taskId == id }; val view = views.getValue(id)
            val allowed = AnalysisPolicy.allowedRefs(run, task)
            ReviewPacketTask(task, view.state, view.reason, view.latestRevision,
                AnalysisMethods.forRun(run).taskDetails(task),
                AnalysisPolicy.requiredRefs(run, task).map { ref -> records.getValue(ref).evidenceId }.sorted(),
                allowed.map { ref -> records.getValue(ref).evidenceId }.sorted())
        }
        val evidence = records.values.sortedBy { it.evidenceId }.map { record ->
            // Read validates identity and both code digests before copying any user-facing material.
            EvidenceFiles.read(runDir, run.runId, record.evidenceId)
            val folder = outDir.resolve("evidence/${record.evidenceId}"); Files.createDirectories(folder)
            fun copy(file: String, name: String): Artifact = Digests.artifact(folder.resolve(name).also { Files.copy(runDir.resolve(file), it) })
            ReviewPacketEvidence(record.evidenceId, record.ref, copy(record.javaPath, "code.java"),
                record.smaliPath?.let { copy(it, "code.smali") }, record.incomplete, record.diagnostics)
        }
        val packet = ReviewPacket(runId = run.runId, apkSha256 = run.apk.sha256, engineBuildId = run.engineBuildId,
            tasks = selected, sharedEvidence = evidence)
        val packetPath = outDir.resolve("review-packet.json"); JsonFiles.writeNew(packetPath, packet)
        val templatePath = outDir.resolve("review-template.json"); JsonFiles.writeNew(templatePath, template(run, selected))
        val summaryPath = outDir.resolve("summary.md"); Files.writeString(summaryPath, summary(packet))
        val result = ReviewPacketResult(runId = run.runId, taskIds = taskIds.sorted(), packetPath = packetPath.toAbsolutePath().toString(),
            templatePath = templatePath.toAbsolutePath().toString(), summaryPath = summaryPath.toAbsolutePath().toString(),
            files = (listOf(packetPath, templatePath, summaryPath).map(Digests::artifact) + evidence.flatMap { listOfNotNull(it.javaFile, it.smaliFile) }).sortedBy { it.path })
        JsonFiles.writeNew(outDir.resolve("packet-manifest.json"), result)
        return result
    }

    fun validate(outDir: Path, runDir: Path, taskIds: Set<String>): ReviewPacketResult {
        val run = AnalysisService.readRun(runDir)
        val result = JsonFiles.read(outDir.resolve("packet-manifest.json"), ReviewPacketResult::class.java)
        requireInput(result.kind == "analysis-review-packet-manifest" && result.runId == run.runId && result.taskIds == taskIds.sorted(), "Review packet belongs to another run or selection")
        val root = outDir.toAbsolutePath().normalize()
        result.files.forEach { file ->
            requireInput(Path.of(file.path).toAbsolutePath().normalize().startsWith(root), "Review packet file escapes its directory")
            Digests.verify(file)
        }
        requireInput(listOf(result.packetPath, result.templatePath, result.summaryPath).all { path -> result.files.any { it.path == path } }, "Incomplete review packet output manifest")
        val packet = JsonFiles.read(Path.of(result.packetPath), ReviewPacket::class.java)
        requireInput(packet.runId == run.runId && packet.apkSha256 == run.apk.sha256 && packet.engineBuildId == run.engineBuildId,
            "Review packet input identity mismatch")
        requireInput(packet.tasks.map { it.task.taskId }.sorted() == taskIds.sorted(), "Review packet selection mismatch")
        val evidence = packet.sharedEvidence.associateBy { it.evidenceId }
        requireInput(evidence.size == packet.sharedEvidence.size, "Duplicate review packet evidence")
        packet.tasks.forEach { item ->
            requireInput(item.task == run.tasks.singleOrNull { it.taskId == item.task.taskId }, "Review packet task or proof changed")
            val allowed = AnalysisPolicy.allowedRefs(run, item.task).map { Identities.evidenceId(run.runId, it) }.sorted()
            val required = AnalysisPolicy.requiredRefs(run, item.task).map { Identities.evidenceId(run.runId, it) }.sorted()
            requireInput(item.evidenceIds == allowed && item.requiredEvidenceIds == required && allowed.all { it in evidence }, "Review packet evidence associations changed")
            requireInput(item.methodDetails == AnalysisMethods.forRun(run).taskDetails(item.task), "Review packet method details changed")
        }
        packet.sharedEvidence.forEach { entry ->
            val original = EvidenceFiles.read(runDir, run.runId, entry.evidenceId)
            requireInput(entry.ref == original.ref && entry.javaFile.sha256 == original.javaSha256 && entry.smaliFile?.sha256 == original.smaliSha256 &&
                entry.incomplete == original.incomplete && entry.diagnostics == original.diagnostics, "Review packet code differs from run evidence")
            requireInput(listOfNotNull(entry.javaFile, entry.smaliFile).all { it in result.files }, "Review packet code missing from output manifest")
        }
        return result
    }

    private fun template(run: AnalysisRun, tasks: List<ReviewPacketTask>): JsonObject = JsonObject().apply {
        addProperty("schemaVersion", SCHEMA_VERSION); addProperty("runId", run.runId); addProperty("apkSha256", run.apk.sha256)
        add("items", JsonArray().apply {
            tasks.filter { it.task.executionState == AnalysisExecutionState.EXECUTED && it.task.invalidReason == null && it.task.resolution?.status == ResolutionStatus.UNIQUE }.forEach { item ->
                add(JsonObject().apply {
                    addProperty("taskId", item.task.taskId); addProperty("resolutionId", item.task.resolution!!.resolutionId)
                    addProperty("ruleRevisionId", item.task.rule.revisionId)
                    add("action", JsonNull.INSTANCE); add("level", JsonNull.INSTANCE)
                    val name = item.task.existingEntry?.name ?: item.task.request.proposedName
                    if (name == null) add("name", JsonNull.INSTANCE) else addProperty("name", name)
                    addProperty("rationale", ""); add("unverified", JsonArray())
                    add("evidenceIds", JsonFiles.gson.toJsonTree(item.evidenceIds))
                    item.latestRevision?.let { addProperty("supersedes", it) }
                })
            }
        })
    }

    private fun summary(packet: ReviewPacket): String = buildString {
        appendLine("# Analysis review packet"); appendLine(); appendLine("Run: `${packet.runId}`")
        appendLine("Read the code and decide semantics. Copy `review-template.json` to a separate review file; the template has no accepted decision.")
        appendLine("Mapping still requires a UNIQUE current result and a valid submitted Review. Invalid and inherited tasks need no new Review.")
        packet.tasks.forEach { item ->
            appendLine(); appendLine("## ${item.task.taskId}")
            appendLine("- State: ${item.state} (${item.reason}); matching: ${item.task.resolution?.status ?: item.task.executionState}")
            appendLine("- Name: ${item.task.existingEntry?.name ?: item.task.request.proposedName ?: "needs semantic naming"}")
            appendLine("- Identity: ${item.task.resolution?.uniqueRef?.descriptor ?: "no unique class"}; semanticId: ${item.task.semanticId ?: "unassigned"}")
            if (item.methodDetails.size() > 0) appendLine("- Method details: `${item.methodDetails}`")
            if (item.task.identitySourceKnowledgeId != null) appendLine("- Canonical referenced name must be preserved; defer if disputed.")
            appendLine("- Required evidence: ${item.requiredEvidenceIds.joinToString()}")
            item.evidenceIds.forEach { id ->
                val e = packet.sharedEvidence.single { it.evidenceId == id }
                appendLine("  - ${e.ref.descriptor}: [Java](${e.javaFile.path.replace('\\', '/')})${e.smaliFile?.let { "; [Smali](${it.path.replace('\\', '/')})" } ?: ""}${if (e.incomplete) " — partial decompilation; state limitations in Review" else ""}")
            }
        }
    }
}
