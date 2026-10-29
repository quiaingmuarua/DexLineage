package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class V02ImporterTest {
    @TempDir lateinit var temp: Path
    private data class Fixture(val bundle: Path, val apk: Artifact, val knowledge: VersionKnowledge)

    /** Metadata and files fixture, not a synthetic APK or claim of DEX execution. */
    private fun fixture(incomplete: Boolean = false): Fixture {
        val apk = Digests.artifact(Files.writeString(temp.resolve("input"), "opaque apk bytes"))
        val bundle = Files.createDirectory(temp.resolve("legacy"))
        val ref = ClassRef(apk.sha256, "La;", "classes.dex")
        val runId = "original-run"
        val evidenceId = Identities.evidenceId(runId, ref)
        val folder = Files.createDirectories(bundle.resolve("evidence/$evidenceId"))
        val code = Files.writeString(folder.resolve("code.java"), "class a { /* partial in fixture */ }")
        val evidence = KnowledgeEvidence(evidenceId, ref, "evidence/$evidenceId/code.java", Digests.file(code), null, null, incomplete, emptyList())
        val taskId = Digests.text("bootstrap-task\n${apk.sha256}\nLa;")
        val semanticId = Digests.text("semantic\n${apk.sha256}\nLa;")
        val captures = mapOf("component" to "Cache")
        val review = JsonFiles.gson.toJsonTree(linkedMapOf("taskId" to taskId, "action" to "ACCEPT", "name" to "Cache", "level" to "HIGH",
            "rationale" to "Owner manages cache", "unverified" to if (incomplete) listOf("Unrelated method not recovered") else emptyList(), "evidenceIds" to listOf(evidenceId))).asJsonObject
        val revision = Digests.text(JsonFiles.encode(StoredReview(schemaVersion = 2, revisionId = "", runId = runId, taskId = taskId, supersedes = null, payload = review)))
        val entry = KnowledgeEntry(semanticId, "Cache", ref, captures, listOf(Locator("string-use", "Cache")), listOf(evidence), "Owner manages cache", "bootstrap:$runId:$revision")
        val draft = VersionKnowledge(schemaVersion = 2, knowledgeId = "", artifact = apk, entries = listOf(entry), unresolved = emptyList(), provenance = "bootstrap:$runId")
        val knowledge = draft.copy(knowledgeId = Digests.text(JsonFiles.encode(draft)))
        JsonFiles.writeNew(bundle.resolve("knowledge.json"), knowledge)
        JsonFiles.writeNew(bundle.resolve("report.json"), mapOf("schemaVersion" to 2, "scenario" to "bootstrap", "runId" to runId,
            "knowledgeId" to knowledge.knowledgeId, "apk" to apk, "profile" to mapOf("minConfidence" to "HIGH"),
            "scan" to MigrationFixtures.stats, "counts" to mapOf("UNREVIEWED" to 0, "ACCEPTED" to 1, "REJECTED" to 0, "DEFERRED" to 0),
            "reviewRevisions" to mapOf(taskId to revision), "decisions" to listOf(mapOf("taskId" to taskId, "name" to "Cache", "state" to "ACCEPTED",
                "proposalId" to Digests.text("proposal\n${apk.sha256}\nLa;\n${JsonFiles.encode(captures)}"), "review" to review))))
        Files.writeString(bundle.resolve("mapping.tiny"), "tiny\t2\t0\tobfuscated\tnamed\nc\ta\tCache\n")
        return Fixture(bundle, apk, knowledge)
    }

    private fun migrationFixture(level: Confidence = Confidence.HIGH): Fixture {
        val f = fixture()
        val old = f.knowledge.entries.single()
        val runId = "original-run"
        val source = Artifact("historical-source", "d".repeat(64))
        val ref = ClassRef(source.sha256, "Lsource;", "classes.dex")
        val evidenceId = Identities.evidenceId(runId, ref)
        val folder = Files.createDirectories(f.bundle.resolve("evidence/$evidenceId"))
        val code = Files.writeString(folder.resolve("code.java"), "class source {}")
        val sourceEvidence = KnowledgeEvidence(evidenceId, ref, "evidence/$evidenceId/code.java", Digests.file(code), null, null, false, emptyList())
        val sourceEntry = old.copy(binding = ref, evidence = listOf(sourceEvidence), provenance = "historical-source")
        val allEvidence = old.evidence + sourceEvidence
        val review = JsonFiles.gson.toJsonTree(linkedMapOf("taskId" to old.semanticId, "targetDescriptor" to old.binding.descriptor,
            "action" to "ACCEPT", "level" to level.name, "nameStillApplies" to true, "identityReason" to old.rationale,
            "changes" to emptyList<String>(), "unverified" to emptyList<String>(), "evidenceIds" to allEvidence.map { it.evidenceId },
            "candidateComparisons" to emptyList<String>())).asJsonObject
        val revision = Digests.text(JsonFiles.encode(StoredReview(schemaVersion = 2, revisionId = "", runId = runId, taskId = old.semanticId, supersedes = null, payload = review)))
        val migrated = old.copy(evidence = allEvidence, provenance = "migration:$runId:$revision")
        val draft = f.knowledge.copy(knowledgeId = "", entries = listOf(migrated), provenance = "migration:$runId")
        val knowledge = draft.copy(knowledgeId = Digests.text(JsonFiles.encode(draft)))
        val matches = MigrationFixtures.proof(old.binding, old.locators).matches
        Files.writeString(f.bundle.resolve("knowledge.json"), JsonFiles.encode(knowledge))
        Files.writeString(f.bundle.resolve("report.json"), JsonFiles.encode(mapOf("schemaVersion" to 2, "kind" to "migration-report", "runId" to runId,
            "sourceKnowledgeId" to "prior-knowledge", "knowledgeId" to knowledge.knowledgeId, "sourceApk" to source, "targetApk" to f.apk,
            "sourceScan" to MigrationFixtures.stats, "targetScan" to MigrationFixtures.stats, "accepted" to 1, "unresolved" to 0, "carriedUnresolved" to 0,
            "reviewRevisions" to mapOf(old.semanticId to revision),
            "tasks" to listOf(mapOf("taskId" to old.semanticId, "entry" to sourceEntry, "candidates" to listOf(mapOf("ref" to old.binding, "status" to "PASS", "matches" to matches)), "matches" to matches)),
            "decisions" to listOf(mapOf("taskId" to old.semanticId, "name" to old.name, "state" to "ACCEPTED", "target" to old.binding, "revisionId" to revision, "review" to review)))))
        return f.copy(knowledge = knowledge)
    }

    private fun convert(f: Fixture, name: String = "converted", targets: List<Pair<String, MatchStatus>> = listOf("La;" to MatchStatus.PASS)): VersionKnowledge =
        V02Importer.importWithExecutor(f.bundle.resolve("knowledge.json"), Path.of(f.apk.path), temp.resolve(name)) { artifact, rules, _ ->
            val resolutions = rules.associate { rule -> rule.revisionId to RuleProofs.create(artifact.sha256, rule, "fixture-engine", targets.flatMap { (descriptor, status) ->
                MigrationFixtures.proof(ClassRef(artifact.sha256, descriptor, "classes.dex"), rule.locators, status).matches
            }) }
            ResolutionBatch(resolutions, ScanResult(mapOf("La;" to "classes.dex", "Lb;" to "classes.dex"), emptyMap(), MigrationFixtures.stats), null)
        }

    @Test fun `same unique binding reuses original semantic review including acknowledged partial code`() {
        val f = fixture(true)
        val originals = Files.list(f.bundle).use { paths -> paths.filter(Files::isRegularFile).toList().associateWith(Digests::file) }
        val value = convert(f)
        val entry = value.entries.single()
        assertEquals(f.knowledge.entries.single().semanticId, entry.semanticId)
        assertEquals(f.knowledge.entries.single().rationale, entry.rationale)
        assertEquals(ResolutionStatus.UNIQUE, entry.resolution!!.status)
        assertTrue(entry.evidence.single().incomplete)
        assertEquals(f.knowledge.knowledgeId, value.parentKnowledgeId)
        assertEquals(value, KnowledgeFiles.read(temp.resolve("converted/knowledge.json")))
        assertEquals(originals, originals.keys.associateWith(Digests::file))
    }

    @Test fun `ambiguous unknown missing and different unique bindings become pending without changing identity`() {
        val f = fixture()
        val cases = listOf(listOf("La;" to MatchStatus.PASS, "Lb;" to MatchStatus.PASS), listOf("La;" to MatchStatus.UNKNOWN), emptyList(), listOf("Lb;" to MatchStatus.PASS))
        cases.forEachIndexed { index, targets ->
            val value = convert(f, "case-$index", targets)
            assertTrue(value.entries.isEmpty())
            assertEquals(f.knowledge.entries.single(), value.unresolved.single().entry)
            assertEquals(f.knowledge.knowledgeId, value.unresolved.single().sourceKnowledgeId)
            assertEquals(1, Files.readAllLines(temp.resolve("case-$index/mapping.tiny")).size)
        }
    }

    @Test fun `malformed review provenance is rejected before output exists`() {
        val f = fixture()
        val reportPath = f.bundle.resolve("report.json")
        val report = com.google.gson.JsonParser.parseString(Files.readString(reportPath)).asJsonObject
        report.getAsJsonArray("decisions")[0].asJsonObject.getAsJsonObject("review").addProperty("rationale", "changed without a new revision")
        Files.writeString(reportPath, JsonFiles.encode(report))
        assertFailsWith<ValidationException> { convert(f) }
        assertFalse(Files.exists(temp.resolve("converted")))
    }

    @Test fun `evidence or mapping damage cannot silently downgrade confirmed knowledge`() {
        val f = fixture()
        Files.writeString(f.bundle.resolve("mapping.tiny"), "tiny\t2\t0\tobfuscated\tnamed\nc\tb\tCache\n")
        assertFailsWith<ValidationException> { convert(f, "wrong-map") }
        Files.writeString(f.bundle.resolve("mapping.tiny"), "tiny\t2\t0\tobfuscated\tnamed\nc\ta\tCache\n")
        Files.writeString(f.bundle.resolve(f.knowledge.entries.single().evidence.single().javaPath), "tampered")
        assertFailsWith<ValidationException> { convert(f, "wrong-evidence") }
        assertFalse(Files.exists(temp.resolve("wrong-evidence")))
    }

    @Test fun `an APK with the wrong digest cannot be used to rebind legacy knowledge`() {
        val f = fixture()
        val other = Files.writeString(temp.resolve("other"), "other bytes")
        assertFailsWith<ValidationException> { V02Importer.importWithExecutor(f.bundle.resolve("knowledge.json"), other, temp.resolve("bad")) { _, _, _ -> error("Must not execute") } }
    }
    @Test fun `migration publication validates its old source and accepts HIGH review reuse`() {
        val f = migrationFixture()
        val value = convert(f)
        assertEquals(f.knowledge.entries.single().semanticId, value.entries.single().semanticId)
        assertEquals(2, value.entries.single().evidence.size)
    }

    @Test fun `legacy migration needs verifiable confidence threshold proof`() {
        val f = migrationFixture(Confidence.MEDIUM)
        assertFailsWith<ValidationException> { convert(f) }
        assertFalse(Files.exists(temp.resolve("converted")))
    }
}
