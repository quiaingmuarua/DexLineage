package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.migration.legacy.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class V03ImporterTest {
    @TempDir lateinit var temp: Path
    private data class Fixture(val root: Path, val apk: Artifact, val knowledge: V03Knowledge)

    private fun fixture(partial: Boolean = false): Fixture {
        val root = Files.createDirectory(temp.resolve("schema3"))
        val apk = Digests.artifact(Files.writeString(temp.resolve("apk-input"), "public fixture bytes"))
        val ref = ClassRef(apk.sha256, "La;", "classes.dex")
        val run = "schema3-original-run"
        val id = Identities.evidenceId(run, ref)
        val dir = Files.createDirectories(root.resolve("evidence/$id"))
        val java = Files.writeString(dir.resolve("code.java"), if (partial) "class a { /* one unrelated method unavailable */ }" else "class a {}")
        val evidence = KnowledgeEvidence(id, ref, "evidence/$id/code.java", Digests.file(java), null, null, partial, if (partial) listOf("partial method") else emptyList())
        val locators = listOf(Locator("string-use", "SourceComponent"))
        val rule = V03Rule(Digests.text(JsonFiles.encode(locators)), locators)
        val fact = V03Match(ref, MatchStatus.PASS, listOf(FactorResult("anchor", MatchStatus.PASS, "public fixture fact")), mapOf("literal" to "SourceComponent"))
        val draft = V03Resolution(3, "", apk.sha256, rule, "0.3.0", "old-engine", "apk-all-dex", ResolutionStatus.UNIQUE, listOf(V03Candidate(ref, MatchStatus.PASS, listOf(fact))), listOf(fact))
        val proof = draft.copy(resolutionId = Digests.text(JsonFiles.encode(draft)))
        val review = JsonFiles.gson.toJsonTree(linkedMapOf("taskId" to "cache", "resolutionId" to proof.resolutionId, "ruleRevisionId" to rule.revisionId,
            "action" to "ACCEPT", "name" to "Cache", "level" to "HIGH", "rationale" to "Manages the fixture cache",
            "unverified" to if (partial) listOf("Unrelated method was not reviewed") else emptyList(), "evidenceIds" to listOf(id))).asJsonObject
        val revision = Digests.text(JsonFiles.encode(StoredReview(3, "", run, "cache", null, review)))
        val entry = V03Entry("cache", "Cache", ref, mapOf("literal" to "SourceComponent"), locators, listOf(evidence), "Manages the fixture cache", "analysis:$run:$revision", rule, proof)
        val value = V03Knowledge(3, "version-knowledge", "", apk, listOf(entry), emptyList(), "analysis:$run")
        val knowledge = value.copy(knowledgeId = Digests.text(JsonFiles.encode(value)))
        JsonFiles.writeNew(root.resolve("knowledge.json"), knowledge)
        JsonFiles.writeNew(root.resolve("report.json"), mapOf("schemaVersion" to 3, "kind" to "analysis-report", "runId" to run,
            "knowledgeId" to knowledge.knowledgeId, "apk" to apk, "confirmed" to 1, "unresolved" to 0, "scan" to MigrationFixtures.stats,
            "reviewRevisions" to mapOf("cache" to revision), "tasks" to listOf(mapOf("taskId" to "cache", "resolution" to proof)),
            "decisions" to listOf(mapOf("taskId" to "cache", "semanticId" to "cache", "name" to "Cache", "state" to "ACCEPTED", "target" to ref, "review" to review))))
        Files.writeString(root.resolve("mapping.tiny"), "tiny\t2\t0\tobfuscated\tnamed\nc\ta\tCache\n")
        return Fixture(root, apk, knowledge)
    }

    private fun import(f: Fixture, output: String, results: List<Pair<String, MatchStatus>> = listOf("La;" to MatchStatus.PASS), history: List<Path> = emptyList()) =
        V03Importer.importWithExecutor(f.root.resolve("knowledge.json"), Path.of(f.apk.path), temp.resolve(output), history) { artifact, rules, _ ->
            val resolutions = rules.associate { rule -> rule.revisionId to RuleProofs.create(artifact.sha256, rule, "new-engine", results.map { (descriptor, state) ->
                MatchFact(ClassRef(artifact.sha256, descriptor, "classes.dex"), state, listOf(FactorResult("anchor", state, "reexecuted fixture")), mapOf("literal" to "SourceComponent"))
            }) }
            ResolutionBatch(resolutions, ScanResult(mapOf("La;" to "classes.dex", "Lb;" to "classes.dex"), emptyMap(), MigrationFixtures.stats), null)
        }

    @Test fun `exact schema3 hashes and acknowledged partial review survive a unique same-binding import`() {
        val f = fixture(true)
        val before = Digests.file(f.root.resolve("knowledge.json"))
        val imported = import(f, "out")
        assertEquals(SCHEMA_VERSION, imported.schemaVersion)
        assertEquals(f.knowledge.entries.single().binding, imported.entries.single().binding)
        assertEquals(TOOL_VERSION, imported.entries.single().resolution!!.engineVersion)
        assertTrue(imported.entries.single().evidence.single().incomplete)
        assertEquals(imported, KnowledgeFiles.read(temp.resolve("out/knowledge.json")))
        assertEquals(before, Digests.file(f.root.resolve("knowledge.json")))
        assertEquals(Files.readString(f.root.resolve("knowledge.json")), Files.readString(temp.resolve("out/legacy/${f.knowledge.knowledgeId}/knowledge.json")))
    }

    @Test fun `fresh ambiguity unknown absence and a different unique owner retain history without a current binding`() {
        val f = fixture()
        val cases = listOf(listOf("La;" to MatchStatus.PASS, "Lb;" to MatchStatus.PASS), listOf("La;" to MatchStatus.UNKNOWN), emptyList(), listOf("Lb;" to MatchStatus.PASS))
        cases.forEachIndexed { i, result ->
            val value = import(f, "out-$i", result)
            assertTrue(value.entries.isEmpty())
            assertEquals(f.knowledge.entries.single().binding, value.unresolved.single().entry.binding)
            assertEquals(f.knowledge.knowledgeId, value.unresolved.single().sourceKnowledgeId)
            assertNull(value.unresolved.single().entry.resolution, "Historical schema3 proof is preserved in legacy/, not relabelled schema4")
        }
    }

    @Test fun `inherited reviews require explicitly supplied original history`() {
        val original = fixture()
        val nextRoot = Files.createDirectory(temp.resolve("schema3-child"))
        val entry = original.knowledge.entries.single()
        entry.evidence.forEach { KnowledgeFiles.copyEvidence(original.root, nextRoot, it) }
        val draft = original.knowledge.copy(knowledgeId = "", provenance = "analysis:next-run", parentKnowledgeId = original.knowledge.knowledgeId)
        val knowledge = draft.copy(knowledgeId = Digests.text(JsonFiles.encode(draft)))
        JsonFiles.writeNew(nextRoot.resolve("knowledge.json"), knowledge)
        JsonFiles.writeNew(nextRoot.resolve("report.json"), mapOf("schemaVersion" to 3, "kind" to "analysis-report", "runId" to "next-run",
            "knowledgeId" to knowledge.knowledgeId, "apk" to knowledge.artifact, "confirmed" to 1, "unresolved" to 0,
            "scan" to MigrationFixtures.stats, "tasks" to emptyList<Any>(), "decisions" to emptyList<Any>(), "reviewRevisions" to emptyMap<String, String>()))
        Files.copy(original.root.resolve("mapping.tiny"), nextRoot.resolve("mapping.tiny"))
        val child = Fixture(nextRoot, original.apk, knowledge)
        assertFailsWith<ValidationException> { import(child, "missing-history") }
        assertFalse(Files.exists(temp.resolve("missing-history")))
        assertEquals(1, import(child, "with-history", history = listOf(original.root.resolve("knowledge.json"))).entries.size)
    }

    @Test fun `tampered original review or missing code fails before execution`() {
        val f = fixture()
        val reportPath = f.root.resolve("report.json")
        val report = com.google.gson.JsonParser.parseString(Files.readString(reportPath)).asJsonObject
        report.getAsJsonArray("decisions")[0].asJsonObject.getAsJsonObject("review").addProperty("rationale", "modified")
        Files.writeString(reportPath, JsonFiles.encode(report))
        assertFailsWith<ValidationException> { import(f, "tampered") }
        assertFalse(Files.exists(temp.resolve("tampered")))
    }
}
