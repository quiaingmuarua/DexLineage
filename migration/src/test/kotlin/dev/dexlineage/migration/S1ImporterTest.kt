package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import dev.dexlineage.migration.legacy.*
import dev.dexlineage.model.Artifact
import dev.dexlineage.model.ClassRef
import dev.dexlineage.model.Confidence
import dev.dexlineage.model.EvidenceRecord
import dev.dexlineage.model.StringUseSite
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class S1ImporterTest {
    @TempDir lateinit var temp: Path
    private data class Fixture(val dir: Path, val out: Path, val run: RunSnapshot, val baseline: Baseline)
    private fun fixture(): Fixture {
        val source = Digests.artifact(Files.writeString(temp.resolve("source-input"), "old input bytes"))
        val target = Digests.artifact(Files.writeString(temp.resolve("target-input"), "new input bytes"))
        val project = temp.resolve("source.jadx")
        JsonFiles.writeNew(project, mapOf("projectVersion" to 1, "files" to listOf(source.path), "codeData" to mapOf("renames" to listOf(
            mapOf("nodeRef" to mapOf("refType" to "CLASS", "declClass" to "a"), "newName" to "Cache"),
            mapOf("nodeRef" to mapOf("refType" to "CLASS", "declClass" to "b"), "newName" to "MissingCache")))))
        val oldA = ClassRef(source.sha256, "La;", "classes.dex")
        val oldB = ClassRef(source.sha256, "Lb;", "classes.dex")
        val newX = ClassRef(target.sha256, "Lx;", "classes2.dex")
        fun candidate(ref: ClassRef, literal: String) = Candidate(ref, listOf(StringUseSite(ref.dexEntry, ref.descriptor, "${ref.descriptor}->a()V", 0, 0, literal)))
        val items = listOf(RunItem("cache", "Cache", oldA, StringRule("cache literal"), true, listOf(candidate(oldA, "cache literal")), listOf(candidate(newX, "cache literal"))),
            RunItem("missing", "MissingCache", oldB, StringRule("missing literal"), true, listOf(candidate(oldB, "missing literal")), emptyList()))
        var run = RunSnapshot(runId = "", caseId = "public-fixture", sourceApk = source, targetApk = target, sourceJadx = Digests.artifact(project),
            items = items, targetDescriptors = listOf("Lx;"), sourceScan = MigrationFixtures.stats, targetScan = MigrationFixtures.stats, createdAt = "old-time")
        run = run.copy(runId = run.fingerprint())
        val dir = Files.createDirectory(temp.resolve("s1-run"))
        JsonFiles.writeNew(dir.resolve("run.json"), run)
        val evidence = listOf(oldA, newX).map { ref ->
            val id = Identities.evidenceId(run.runId, ref)
            val folder = Files.createDirectories(dir.resolve("evidence/$id"))
            val java = Files.writeString(folder.resolve("code.java"), "class ${Identities.rawName(ref.descriptor)} {}")
            EvidenceRecord(schemaVersion = 1, evidenceId = id, runId = run.runId, ref = ref, javaPath = "evidence/$id/code.java", javaSha256 = Digests.file(java),
                smaliPath = null, smaliSha256 = null, incomplete = false, diagnostics = emptyList(), elapsedMillis = 0).also { JsonFiles.writeNew(folder.resolve("record.json"), it) }
        }
        val review = ReviewItem("cache", "Lx;", Confidence.HIGH, true, "Both owners cache providers", listOf("Implementation changed"), emptyList(), evidence.map { it.evidenceId })
        val decisions = listOf(Decision("cache", "Cache", DecisionStatus.ACCEPTED, "review_supported", oldA, items[0].rule, newX, review),
            Decision("missing", "MissingCache", DecisionStatus.PENDING, "no_candidates", oldB, items[1].rule, null, null))
        val baseline = Baseline(runId = run.runId, artifact = target, items = decisions.map { BaselineItem(it.id, it.semanticName, it.status, it.reason, it.source, it.rule, it.target) })
        val report = MigrationReport(runId = run.runId, sourceApk = source, targetApk = target, reviewSha256 = Digests.text(JsonFiles.encode(review)), accepted = 1, pending = 1,
            decisions = decisions, sourceScan = run.sourceScan, targetScan = run.targetScan)
        val out = Files.createDirectory(temp.resolve("s1-out"))
        JsonFiles.writeNew(out.resolve("baseline.json"), baseline)
        JsonFiles.writeNew(out.resolve("report.json"), report)
        Files.writeString(out.resolve("mapping.tiny"), "tiny\t2\t0\tobfuscated\tnamed\nc\tx\tCache\n")
        return Fixture(dir, out, run, baseline)
    }
    private fun convert(output: Path, run: Path, destination: Path, ambiguous: Boolean = false) = S1Importer.importWithExecutor(output, run, destination) { artifact, rules, _ ->
        val refs = (if (ambiguous) listOf("Lx;", "Ly;") else listOf("Lx;")).map { ClassRef(artifact.sha256, it, "classes2.dex") }
        ResolutionBatch(rules.associate { rule -> rule.revisionId to RuleProofs.create(artifact.sha256, rule, "fixture-engine", refs.flatMap { MigrationFixtures.proof(it, rule.locators).matches }) },
            ScanResult(refs.associate { it.descriptor to it.dexEntry }, emptyMap(), MigrationFixtures.stats), null)
    }
    @Test fun `explicit S1 conversion retains only confirmed current bindings and original pending knowledge`() {
        val f = fixture()
        val before = listOf(f.dir.resolve("run.json"), f.out.resolve("baseline.json"), f.out.resolve("report.json"), Path.of(f.run.sourceJadx.path)).associateWith(Digests::file)
        val destination = temp.resolve("v3-knowledge")
        val converted = convert(f.out, f.dir, destination)
        assertEquals(converted, KnowledgeFiles.read(destination.resolve("knowledge.json")))
        val accepted = converted.entries.single()
        assertEquals("Cache", accepted.name)
        assertEquals("Lx;", accepted.binding.descriptor)
        assertEquals(f.run.targetApk.sha256, accepted.binding.apkSha256)
        assertEquals("cache literal", accepted.locators.single().anchor)
        assertEquals("string-use", accepted.locators.single().kind)
        assertEquals(2, accepted.evidence.size)
        assertEquals(ResolutionStatus.UNIQUE, accepted.resolution!!.status)
        assertEquals(accepted.binding, accepted.resolution!!.uniqueRef)
        val pending = converted.unresolved.single()
        assertEquals(f.run.items[1].source, pending.entry.binding)
        assertEquals("missing literal", pending.entry.locators.single().anchor)
        assertEquals("s1:${f.run.runId}", pending.sourceKnowledgeId)
        assertEquals(before, before.keys.associateWith(Digests::file))
    }
    @Test fun `baseline report disagreement cannot be converted`() {
        val f = fixture()
        Files.writeString(f.out.resolve("baseline.json"), JsonFiles.encode(f.baseline.copy(items = f.baseline.items.map { it.copy(semanticName = "Fabricated") })))
        assertFailsWith<ValidationException> { convert(f.out, f.dir, temp.resolve("bad")) }
        assertFalse(Files.exists(temp.resolve("bad")))
    }
    @Test fun `S1 run tampering and extra Mapping classes are rejected`() {
        val f = fixture()
        Files.writeString(f.dir.resolve("run.json"), JsonFiles.encode(f.run.copy(caseId = "changed")))
        assertFailsWith<ValidationException> { convert(f.out, f.dir, temp.resolve("bad-run")) }
        Files.writeString(f.dir.resolve("run.json"), JsonFiles.encode(f.run))
        Files.writeString(f.out.resolve("mapping.tiny"), "tiny\t2\t0\tobfuscated\tnamed\nc\tx\tCache\nc\ty\tGuessed\n")
        assertFailsWith<ValidationException> { convert(f.out, f.dir, temp.resolve("bad-mapping")) }
    }
    @Test fun `missing or modified S1 proof is not silently dropped`() {
        val f = fixture()
        val target = f.run.items.first().targetCandidates.single().ref
        val id = Identities.evidenceId(f.run.runId, target)
        Files.writeString(f.dir.resolve("evidence/$id/code.java"), "modified")
        assertFailsWith<ValidationException> { convert(f.out, f.dir, temp.resolve("bad-proof")) }
    }
    @Test fun `formerly accepted S1 binding must pass the new unique gate`() {
        val f = fixture()
        val output = temp.resolve("ambiguous-upgrade")
        val value = convert(f.out, f.dir, output, ambiguous = true)
        assertTrue(value.entries.isEmpty())
        assertEquals(2, value.unresolved.size)
        val formerlyAccepted = value.unresolved.single { it.entry.semanticId == "cache" }
        assertEquals("Lx;", formerlyAccepted.entry.binding.descriptor)
        assertEquals("invalid_ambiguous", formerlyAccepted.reason)
        assertEquals(1, Files.readAllLines(output.resolve("mapping.tiny")).size)
    }
}
