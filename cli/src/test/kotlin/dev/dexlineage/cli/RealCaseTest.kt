package dev.dexlineage.cli

import dev.dexlineage.analysis.*
import dev.dexlineage.migration.MigrationService
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import java.util.UUID
import kotlin.test.*

/** Fresh APK matching and saved publication replay prove different claims. */
@Tag("real-case")
class RealCaseTest {
    @Test fun `fresh matching unique-only migration and continued analysis preserve knowledge`() {
        val config = Path.of(requireNotNull(System.getProperty("dexlineage.caseProperties")))
        val properties = Properties().apply { Files.newBufferedReader(config).use(::load) }
        if (properties.getProperty("scenario") == "analysis-workspace") {
            AnalysisWorkspaceAcceptance.run(config)
            return
        }
        if (properties.getProperty("scenario") == "grpc-analysis") {
            GrpcTopicAcceptance.run(config)
            return
        }
        if (properties.getProperty("scenario") == "v04") {
            V04CaseAcceptance.run(config)
            return
        }
        fun path(key: String) = config.toAbsolutePath().parent.resolve(requireNotNull(properties.getProperty(key)) { "Missing $key" }).normalize()
        val analysisDir = path("analysisRun")
        val analysisOutput = path("analysisOutput")
        val migrationDir = path("migrationRun")
        val migrationOutput = path("migrationOutput")
        val continuationDir = path("continuationRun")
        val continuationOutput = path("continuationOutput")
        val failedDir = path("failedUpdateRun")
        val failedOutput = path("failedUpdateOutput")
        val analysis = AnalysisService.readRun(analysisDir)
        val migration = MigrationService.readRun(migrationDir)
        val continuation = AnalysisService.readRun(continuationDir)
        val failed = AnalysisService.readRun(failedDir)
        val initial = KnowledgeFiles.read(analysisOutput.resolve("knowledge.json"))
        val migrated = KnowledgeFiles.read(migrationOutput.resolve("knowledge.json"))
        val continued = KnowledgeFiles.read(continuationOutput.resolve("knowledge.json"))
        val preserved = KnowledgeFiles.read(failedOutput.resolve("knowledge.json"))
        val imported = KnowledgeFiles.read(path("upgradedV02Output").resolve("knowledge.json"))
        val legacy = JsonFiles.read(path("v02Knowledge"), VersionKnowledge::class.java, 2)
        assertTrue(analysis.tasks.isNotEmpty())
        assertEquals(0, AnalysisService.tasks(analysisDir, "UNREVIEWED").total)
        assertEquals(0, MigrationService.tasks(migrationDir, "UNREVIEWED").total)
        assertEquals(0, AnalysisService.tasks(continuationDir, "UNREVIEWED").total)
        assertTrue(analysis.tasks.groupBy { it.rule.revisionId }.values.any { group ->
            group.size > 1 && group.all { it.resolution!!.status == ResolutionStatus.AMBIGUOUS }
        }, "Real duplicate-component cases must stay invalid")
        val invalidBindings = analysis.tasks.filter { it.resolution!!.status != ResolutionStatus.UNIQUE || it.invalidReason != null }
            .mapNotNull { it.expectedOwner }.toSet()
        assertTrue(initial.entries.none { it.binding in invalidBindings })
        assertEquals(initial, migration.knowledge)
        assertEquals(Digests.file(analysisOutput.resolve("knowledge.json")), migration.knowledgeFile.sha256)
        assertEquals(initial.entries.map { it.semanticId }.toSet(), migration.tasks.map { it.taskId }.toSet())
        assertEquals((initial.entries.map { it.semanticId } + initial.unresolved.map { it.entry.semanticId }).toSet(),
            (migrated.entries.map { it.semanticId } + migrated.unresolved.map { it.entry.semanticId }).toSet())
        assertTrue(migrated.entries.isNotEmpty())
        migrated.unresolved.filter { pending -> initial.entries.any { it.semanticId == pending.entry.semanticId } }.forEach { pending ->
            assertEquals(initial.entries.single { it.semanticId == pending.entry.semanticId }, pending.entry)
        }
        assertEquals(migrated, continuation.baseKnowledge)
        assertEquals(migrated.knowledgeId, continued.parentKnowledgeId)
        val updated = continued.entries.filter { now -> migrated.entries.none { it == now } }
        assertTrue(updated.isNotEmpty(), "Continuation must confirm an update or addition")
        migrated.entries.forEach { old -> assertEquals(old.semanticId, continued.entries.single { it.binding == old.binding }.semanticId) }
        assertEquals(migrated.unresolved, continued.unresolved)
        assertEquals(continued, failed.baseKnowledge)
        assertTrue(failed.tasks.isNotEmpty() && failed.tasks.all { it.resolution!!.status != ResolutionStatus.UNIQUE || it.invalidReason != null })
        assertEquals(continued.entries, preserved.entries)
        assertEquals(continued.unresolved, preserved.unresolved)
        assertEquals(Files.readString(continuationOutput.resolve("mapping.tiny")), Files.readString(failedOutput.resolve("mapping.tiny")))
        val historicalIds = (legacy.entries.map { it.semanticId } + legacy.unresolved.map { it.entry.semanticId }).toSet()
        assertEquals(historicalIds, (imported.entries.map { it.semanticId } + imported.unresolved.map { it.entry.semanticId }).toSet())
        assertTrue(imported.entries.isNotEmpty(), "Unique old bindings should retain verified reviews")
        assertTrue(imported.unresolved.any { pending -> legacy.entries.any { it.semanticId == pending.entry.semanticId } }, "Old ambiguity must not inherit confirmation")
        imported.entries.forEach { current ->
            val old = legacy.entries.single { it.semanticId == current.semanticId }
            assertEquals(old.binding, current.binding)
            assertEquals(old.name, current.name)
        }
        val output = path("acceptanceRoot").resolve(UUID.randomUUID().toString())
        Files.createDirectories(output)
        val discovery = requireNotNull(analysis.discovery)
        val newResult = AnalysisService.discover(Path.of(analysis.apk.path), Path.of(discovery.profileSource.path), output.resolve("fresh-discovery"))
        val newDiscovery = JsonFiles.read(Path.of(newResult.discoveryPath), AnalysisDiscovery::class.java)
        assertEquals(discovery.leads, newDiscovery.leads, "Fresh discovery cannot consume saved candidates")
        assertEquals(discovery.matchCounts, newDiscovery.matchCounts)
        val freshSource = ResolutionEngine.execute(analysis.apk, analysis.tasks.map { it.rule }, output.resolve("fresh-source-matches"))
        assertEquals(analysis.tasks.map { it.resolution!! }.associateBy { it.rule.revisionId }, freshSource.resolutions)
        val freshTarget = ResolutionEngine.execute(migration.targetApk, migration.tasks.map { it.resolution!!.rule }, output.resolve("fresh-target-matches"))
        assertEquals(migration.tasks.map { it.resolution!! }.associateBy { it.rule.revisionId }, freshTarget.resolutions)
        AnalysisService.publish(analysisDir, output.resolve("analysis-replay"), analysisOutput.resolve("report.json"))
        MigrationService.publish(migrationDir, output.resolve("migration-replay"), migrationOutput.resolve("report.json"))
        AnalysisService.publish(continuationDir, output.resolve("continuation-replay"), continuationOutput.resolve("report.json"))
        for ((original, replay) in listOf(analysisOutput to output.resolve("analysis-replay"), migrationOutput to output.resolve("migration-replay"), continuationOutput to output.resolve("continuation-replay"))) {
            assertEquals(Files.readString(original.resolve("knowledge.json")), Files.readString(replay.resolve("knowledge.json")))
            assertEquals(Files.readString(original.resolve("mapping.tiny")), Files.readString(replay.resolve("mapping.tiny")))
        }
        fun verify(value: VersionKnowledge, directory: Path, work: String) = MappingOutput.verify(Path.of(value.artifact.path), directory.resolve("mapping.tiny"),
            value.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) }, output.resolve(work))
        val sourceNames = verify(initial, analysisOutput, "source-readback")
        val targetNames = verify(continued, continuationOutput, "target-readback")
        listOf(analysis.apk, migration.targetApk, migration.knowledgeFile, continuation.baseFile!!, failed.baseFile!!).forEach(Digests::verify)
        JsonFiles.writeNew(output.resolve("acceptance.json"), mapOf("schemaVersion" to SCHEMA_VERSION,
            "analysisRunId" to analysis.runId, "migrationRunId" to migration.runId,
            "analysisResolutions" to analysis.tasks.groupingBy { it.resolution!!.status }.eachCount(),
            "analysisConfirmed" to initial.entries.size, "migrationConfirmed" to migrated.entries.size,
            "migrationUnresolved" to migrated.unresolved.size, "continuedConfirmed" to continued.entries.size,
            "continuedUpdatesOrAdditions" to updated.map { it.name }, "failedUpdatePreservedBaseline" to true,
            "legacyUpgraded" to imported.entries.size, "legacyUnresolved" to imported.unresolved.size,
            "freshDiscoveryAndMatchingReproduced" to true, "publicationReplayIdentical" to true,
            "sourceReadback" to sourceNames, "targetReadback" to targetNames))
        println("Real-case acceptance: ${output.resolve("acceptance.json")}")
    }
}
