package dev.dexlineage.cli

import com.google.gson.JsonParser
import dev.dexlineage.analysis.*
import dev.dexlineage.analysis.workspace.WorkspaceService
import dev.dexlineage.analysis.workspace.WorkspaceStageKind
import dev.dexlineage.analysis.workspace.WorkspaceState
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import java.util.UUID
import kotlin.test.*

/** Explicit local regression: the production CLI produces the workspace and actual Agent Reviews first. */
object AnalysisWorkspaceAcceptance {
    fun run(config: Path) {
        val properties = Properties().apply { Files.newBufferedReader(config).use(::load) }
        fun input(key: String) = config.toAbsolutePath().parent.resolve(requireNotNull(properties.getProperty(key)) { "Missing $key" }).normalize()
        val work = input("workspace")
        val baselineDir = input("baselineCase")
        val baselineManifest = JsonParser.parseString(Files.readString(input("baselineManifest"))).asJsonObject
        val preserved = baselineManifest.getAsJsonObject("files").entrySet().map { (path, hash) -> Artifact(path, hash.asString) } +
            JsonFiles.gson.fromJson(baselineManifest.get("apk"), Artifact::class.java)
        preserved.forEach(Digests::verify)
        val status = WorkspaceService.status(work)
        assertEquals(WorkspaceState.COMPLETE, status.state)
        val currentRunDir = Path.of(assertNotNull(status.runPath))
        val current = AnalysisService.readRun(currentRunDir)
        val old = AnalysisService.readRun(baselineDir.resolve("rpc-run"))
        val before = KnowledgeFiles.read(baselineDir.resolve("published/knowledge.json"))
        val publishedFile = Path.of(assertNotNull(status.knowledgePath))
        val after = KnowledgeFiles.read(publishedFile)
        val out = input("acceptanceRoot").resolve(UUID.randomUUID().toString())
        Files.createDirectories(out)

        assertEquals(old.apk, current.apk)
        assertEquals(old.classInventory, current.classInventory)
        assertEquals(old.tasks.map { it.taskId }.toSet(), current.tasks.map { it.taskId }.toSet())
        current.tasks.forEach { task ->
            val previous = old.tasks.single { it.taskId == task.taskId }
            assertEquals(previous.rule, task.rule, "Refactoring cannot silently revise locator semantics")
            assertEquals(previous.semanticId, task.semanticId)
            assertEquals(previous.expectedOwner, task.expectedOwner)
            assertEquals(normalized(previous.resolution!!), normalized(task.resolution!!), "Matching changed for ${task.taskId}")
        }
        fun bindings(value: VersionKnowledge) = value.entries.map { Triple(it.semanticId, it.name, it.binding) }.toSet()
        assertEquals(bindings(before), bindings(after), "The reviewed result set must survive the workflow refactor")
        assertEquals(Files.readString(baselineDir.resolve("published/mapping.tiny")), Files.readString(publishedFile.parent.resolve("mapping.tiny")))
        val packet = ReviewPackets.validate(Path.of(assertNotNull(status.packetPath)), currentRunDir, status.selectedTaskIds.toSet())
        assertEquals(status.selectedTaskIds.toSet(), packet.taskIds.toSet())
        val views = AnalysisService.tasks(currentRunDir, "ALL", limit = Int.MAX_VALUE).items.associateBy { it.task.taskId }
        assertTrue(status.selectedTaskIds.none { views.getValue(it).state == TaskState.UNREVIEWED })

        // Old schema-4 run/proof data is verified in its original wire layout and can still replay.
        val oldReplay = out.resolve("legacy-publication-replay")
        AnalysisService.publish(baselineDir.resolve("rpc-run"), oldReplay, baselineDir.resolve("published/report.json"))
        for (name in listOf("knowledge.json", "mapping.tiny")) {
            assertEquals(Files.readString(baselineDir.resolve("published/$name")), Files.readString(oldReplay.resolve(name)))
        }

        // Reuse the established real-case checks, supplying only the formal workspace's stage products.
        val case = JsonParser.parseString(Files.readString(baselineDir.resolve("case.json"))).asJsonObject
        val rounds = status.stages.filter { it.kind == WorkspaceStageKind.SEED }.map { stage ->
            val product = assertNotNull(stage.product)
            mapOf("run" to work.resolve(assertNotNull(product.runPath)).toString(),
                "output" to work.resolve(assertNotNull(product.knowledgePath)).parent.toString())
        } + mapOf("run" to currentRunDir.toString(), "output" to publishedFile.parent.toString())
        val manifest = out.resolve("reexecution-manifest.json")
        JsonFiles.writeNew(manifest, mapOf("schemaVersion" to SCHEMA_VERSION,
            "baseKnowledge" to case["baseKnowledge"].asString,
            "referenceKnowledge" to listOf(case["referenceKnowledge"].asString), "rounds" to rounds,
            "discovery" to assertNotNull(status.discoveryPath),
            "reviewServices" to case.getAsJsonArray("reviewServices").map { it.asString },
            "requiredPairs" to case.getAsJsonArray("requiredPairs"), "preservedInputs" to preserved))
        val nested = out.resolve("reexecution.properties")
        Files.writeString(nested, "scenario=grpc-analysis\ncaseManifest=reexecution-manifest.json\nacceptanceRoot=proofs\n")
        GrpcTopicAcceptance.run(nested)
        preserved.forEach(Digests::verify)
        JsonFiles.writeNew(out.resolve("acceptance.json"), mapOf("schemaVersion" to SCHEMA_VERSION,
            "kind" to "analysis-workspace-acceptance", "workspaceId" to status.workspaceId,
            "knowledgeId" to after.knowledgeId, "matchingTasksUnchanged" to current.tasks.size,
            "reviewedScope" to status.selectedTaskIds.size, "confirmed" to after.entries.size,
            "normalizedMatchingEqual" to true, "legacyPublicationReplayIdentical" to true,
            "bindingIdentityAndMappingEqual" to true, "packetValidated" to true,
            "newProofs" to out.resolve("proofs").toString(), "preservedInputs" to preserved.size))
    }

    private fun normalized(proof: Resolution): Any = mapOf("rule" to proof.rule, "status" to proof.status,
        "candidates" to proof.candidates, "matches" to proof.matches,
        "dependencies" to proof.dependencies.mapValues { (_, a) -> mapOf("key" to a.key, "binding" to a.binding, "rule" to a.rule) },
        "unresolved" to proof.unresolvedPaths.orEmpty().map { Triple(it.source, it.codeUnitOffset, it.reason) })
}
