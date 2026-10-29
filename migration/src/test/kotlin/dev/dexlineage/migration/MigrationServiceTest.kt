package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.EvidenceFiles
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.knowledge.ReviewStore
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class MigrationServiceTest {
    @TempDir lateinit var temp: Path
    private data class Fixture(val dir: Path, val run: MigrationRun)

    /** File protocol fixture; deliberately never claims to execute a DEX scan. */
    private fun fixture(withOverride: Boolean = false): Fixture {
        val source = Digests.artifact(Files.writeString(temp.resolve("old-input"), "source bytes"))
        val target = Digests.artifact(Files.writeString(temp.resolve("new-input"), "target bytes"))
        val bundle = Files.createDirectory(temp.resolve("source-bundle"))
        val sourceRefs = listOf(ClassRef(source.sha256, "La;", "classes.dex"), ClassRef(source.sha256, "Lb;", "classes.dex"))
        val oldEvidence = EvidenceFiles.publish(bundle, "previous-bootstrap", source, sourceRefs,
            sourceRefs.map { DecompiledClass(it.descriptor, "class ${Identities.rawName(it.descriptor)} {}", null, false, emptyList(), 0) })
        fun entry(index: Int): KnowledgeEntry {
            val locators = listOf(Locator("string-use", "literal$index"))
            val proof = MigrationFixtures.proof(sourceRefs[index], locators)
            return KnowledgeEntry("item-$index", "Cache$index", sourceRefs[index], mapOf("literal" to "literal$index"), locators,
                listOf(oldEvidence[index].let { KnowledgeEvidence(it.evidenceId, it.ref, it.javaPath, it.javaSha256, null, null, false, emptyList()) }),
                "Known owner", "analysis:prior", proof.rule, proof)
        }
        val entries = (0..1).map(::entry)
        val historical = entries[1].copy(semanticId = "historical", binding = ClassRef("d".repeat(64), "Lhistorical;", "classes.dex"), evidence = emptyList(), ruleRevision = null, resolution = null)
        val knowledge = KnowledgeFiles.write(bundle, VersionKnowledge(knowledgeId = "", artifact = source, entries = entries,
            unresolved = listOf(UnresolvedKnowledge(historical, "older-revision", "not found in prior migration", "prior-run")), provenance = "fixture"))
        val ref = ClassRef(target.sha256, "Lx;", "classes2.dex")
        val replacement = if (withOverride) listOf(MigrationRuleOverride("item-0", listOf(Locator("string-use", "new literal")), entries[0].ruleRevision!!.revisionId)) else emptyList()
        val rulesFile = if (withOverride) temp.resolve("rules.json").also { JsonFiles.writeNew(it, MigrationRulesFile(items = replacement)) }.let(Digests::artifact) else null
        val proof = MigrationFixtures.proof(ref, if (withOverride) replacement.single().locators else entries[0].locators)
        var run = MigrationRun(runId = "", knowledgeFile = Digests.artifact(bundle.resolve("knowledge.json")), knowledge = knowledge,
            sourceApk = source, targetApk = target, minConfidence = Confidence.HIGH,
            tasks = listOf(MigrationTask(entries[0].semanticId, entries[0], proof), MigrationTask(entries[1].semanticId, entries[1], RuleProofs.create(target.sha256, entries[1].ruleRevision!!, "fixture-engine", emptyList()))),
            sourceInventory = sourceRefs.associate { it.descriptor to it.dexEntry }, targetInventory = mapOf(ref.descriptor to ref.dexEntry),
            sourceScan = MigrationFixtures.stats, targetScan = MigrationFixtures.stats, analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "fixture", engineBuildId = "fixture-engine", rulesFile = rulesFile, ruleOverrides = replacement)
        run = run.copy(runId = run.fingerprint())
        val dir = Files.createDirectory(temp.resolve("run"))
        JsonFiles.writeNew(dir.resolve("run.json"), run)
        EvidenceFiles.publish(dir, run.runId, source, sourceRefs, sourceRefs.map { DecompiledClass(it.descriptor, "class ${Identities.rawName(it.descriptor)} {}", null, false, emptyList(), 0) })
        EvidenceFiles.publish(dir, run.runId, target, listOf(ref), listOf(DecompiledClass("Lx;", "class x {}", null, false, emptyList(), 0)))
        return Fixture(dir, run)
    }
    private fun submit(f: Fixture, name: String, items: List<MigrationReview>): MigrationSubmission {
        val batch = MigrationReviewBatch(SCHEMA_VERSION, f.run.runId, f.run.knowledge.knowledgeId, f.run.sourceApk.sha256, f.run.targetApk.sha256, items)
        val path = temp.resolve(name)
        JsonFiles.writeNew(path, batch)
        return MigrationService.submit(f.dir, path)
    }
    @Test fun `review resubmission revision recovery and incremental publish preserve knowledge`() {
        val f = fixture()
        val review = MigrationFixtures.review(f.run)
        val first = submit(f, "first.json", listOf(review))
        val identical = submit(f, "identical.json", listOf(review))
        assertEquals(first.revisions, identical.revisions)
        assertEquals(1, ReviewStore.latest(f.dir, f.run.runId).size)
        val firstOut = temp.resolve("published-1")
        val firstPublication = MigrationService.publish(f.dir, firstOut)
        assertEquals(1, firstPublication.accepted)
        assertEquals(2, firstPublication.unresolved)
        val knowledge = KnowledgeFiles.read(firstOut.resolve("knowledge.json"))
        assertEquals(f.run.targetApk, knowledge.artifact)
        assertEquals("literal0", knowledge.entries.single().locators.single().anchor)
        assertEquals(f.run.knowledge.knowledgeId, knowledge.parentKnowledgeId)
        assertEquals(f.run.tasks.first().resolution, knowledge.entries.single().resolution)
        val pending = knowledge.unresolved.single { it.entry.semanticId == "item-1" }
        assertEquals(f.run.tasks[1].entry, pending.entry)
        assertEquals(f.run.knowledge.knowledgeId, pending.sourceKnowledgeId)
        assertNotEquals(knowledge.artifact.sha256, pending.entry.binding.apkSha256)
        assertEquals(f.run.knowledge.unresolved.single(), knowledge.unresolved.single { it.entry.semanticId == "historical" })
        assertEquals(2, Files.readAllLines(firstOut.resolve("mapping.tiny")).size)
        val report = com.google.gson.JsonParser.parseString(Files.readString(firstOut.resolve("report.json"))).asJsonObject
        val metrics = report.getAsJsonObject("evidenceMetrics")
        assertEquals("emitted_or_cached_evidence", metrics["scope"].asString)
        assertFalse(metrics["agentReadsMeasured"].asBoolean)
        assertEquals(3, metrics["ownerApkPairs"].asInt)
        assertEquals(2, metrics["apkCount"].asInt)
        assertEquals(3, metrics["javaLines"].asInt)
        assertEquals(0, metrics["smaliFiles"].asInt)
        val changed = review.copy(identityReason = "Rechecked constructor and cache ownership")
        assertFailsWith<ValidationException> { submit(f, "unversioned-change.json", listOf(changed)) }
        val next = submit(f, "explicit-revision.json", listOf(changed.copy(supersedes = first.revisions.getValue(review.taskId))))
        assertNotEquals(first.revisions, next.revisions)
        assertEquals(TaskState.ACCEPTED, MigrationService.tasks(f.dir, "ACCEPTED", 0, 1).tasks.single().state)
        assertEquals(0, MigrationService.tasks(f.dir, "UNREVIEWED").total)
        assertEquals(0, MigrationService.tasks(f.dir).total)
        assertEquals(2, MigrationService.tasks(f.dir, "ALL").total)
        val nextOut = temp.resolve("published-2")
        MigrationService.publish(f.dir, nextOut)
        assertEquals(firstPublication.knowledgeId, KnowledgeFiles.read(firstOut.resolve("knowledge.json")).knowledgeId)
        assertNotEquals(knowledge.knowledgeId, KnowledgeFiles.read(nextOut.resolve("knowledge.json")).knowledgeId)
        val replayOut = temp.resolve("replayed-first")
        val replay = MigrationService.publish(f.dir, replayOut, firstOut.resolve("report.json"))
        assertEquals(firstPublication.knowledgeId, replay.knowledgeId)
        assertEquals(Files.readString(firstOut.resolve("mapping.tiny")), Files.readString(replayOut.resolve("mapping.tiny")))
        assertFailsWith<ValidationException> { MigrationService.publish(f.dir, nextOut) }
    }
    @Test fun `batch with one stale supersedes commits no other task`() {
        val f = fixture()
        val original = MigrationFixtures.review(f.run)
        submit(f, "existing.json", listOf(original))
        val changed = original.copy(identityReason = "Changed without explicit supersedes")
        val deferred = MigrationFixtures.review(f.run, f.run.tasks[1]).copy(action = ReviewAction.DEFER)
        assertFailsWith<ValidationException> { submit(f, "invalid-batch.json", listOf(deferred, changed)) }
        assertEquals(setOf(original.taskId), ReviewStore.latest(f.dir, f.run.runId).keys)
        assertEquals(TaskState.INVALID, MigrationService.tasks(f.dir, "INVALID").tasks.single().state)
    }
    @Test fun `wrong review run knowledge and APK identities are rejected before persistence`() {
        val f = fixture()
        val good = MigrationReviewBatch(SCHEMA_VERSION, f.run.runId, f.run.knowledge.knowledgeId, f.run.sourceApk.sha256, f.run.targetApk.sha256, listOf(MigrationFixtures.review(f.run)))
        val batches = listOf(good.copy(runId = "other"), good.copy(sourceKnowledgeId = "other"), good.copy(sourceApkSha256 = "other"), good.copy(targetApkSha256 = "other"))
        batches.forEachIndexed { i, batch ->
            val path = temp.resolve("wrong-$i.json")
            JsonFiles.writeNew(path, batch)
            assertFailsWith<ValidationException> { MigrationService.submit(f.dir, path) }
        }
        assertTrue(ReviewStore.latest(f.dir, f.run.runId).isEmpty())
    }
    @Test fun `unchanged disk evidence resumes without loading APKs`() {
        val f = fixture()
        val records = MigrationService.inspect(f.dir, setOf("item-0"))
        assertEquals(setOf(f.run.tasks[0].entry.binding, f.run.tasks[0].candidates.single().ref), records.map { it.ref }.toSet())
        val replay = MigrationService.inspect(f.dir, setOf("item-0"))
        assertEquals(records, replay)
        Files.writeString(f.dir.resolve(records.first().javaPath), "tampered")
        assertFailsWith<ValidationException> { MigrationService.inspect(f.dir, setOf("item-0")) }
    }
    @Test fun `APK changes cannot be hidden by persisted queue or source knowledge`() {
        val f = fixture()
        Files.writeString(Path.of(f.run.sourceApk.path), "changed APK")
        assertFailsWith<ValidationException> { MigrationService.tasks(f.dir) }
        assertFailsWith<ValidationException> { MigrationService.prepare(Path.of(f.run.knowledgeFile.path), Path.of(f.run.sourceApk.path), Path.of(f.run.targetApk.path), temp.resolve("wrong-source")) }
    }
    @Test fun `snapshot policy is bound into run fingerprint`() {
        val f = fixture()
        Files.writeString(f.dir.resolve("run.json"), JsonFiles.encode(f.run.copy(minConfidence = Confidence.LOW)))
        assertFailsWith<ValidationException> { MigrationService.readRun(f.dir) }
    }
    @Test fun `old target selection fields are explicitly refused`() {
        val f = fixture()
        val batch = MigrationReviewBatch(SCHEMA_VERSION, f.run.runId, f.run.knowledge.knowledgeId, f.run.sourceApk.sha256, f.run.targetApk.sha256, listOf(MigrationFixtures.review(f.run)))
        val json = JsonFiles.gson.toJsonTree(batch).asJsonObject
        json.getAsJsonArray("items")[0].asJsonObject.addProperty("targetDescriptor", "Lx;")
        val path = temp.resolve("old-selection.json")
        JsonFiles.writeNew(path, json)
        assertFailsWith<ValidationException> { MigrationService.submit(f.dir, path) }
        assertTrue(ReviewStore.latest(f.dir, f.run.runId).isEmpty())
    }
    @Test fun `publication stores target rule revision while preserving source knowledge`() {
        val f = fixture(withOverride = true)
        val before = Digests.file(Path.of(f.run.knowledgeFile.path))
        submit(f, "new-rule-review.json", listOf(MigrationFixtures.review(f.run)))
        val out = temp.resolve("new-rules-published")
        MigrationService.publish(f.dir, out)
        val published = KnowledgeFiles.read(out.resolve("knowledge.json")).entries.single()
        assertEquals("new literal", published.locators.single().anchor)
        assertEquals(mapOf("literal" to "new literal"), published.captures)
        assertEquals(f.run.tasks.first().resolution!!.rule, published.ruleRevision)
        assertNotEquals(f.run.tasks.first().entry.ruleRevision, published.ruleRevision)
        assertEquals(before, Digests.file(Path.of(f.run.knowledgeFile.path)))
        val stale = MigrationFixtures.review(f.run).copy(ruleRevisionId = f.run.tasks.first().entry.ruleRevision!!.revisionId)
        assertFailsWith<ValidationException> { submit(f, "stale-rule-review.json", listOf(stale)) }
    }
    @Test fun `unknown override properties cannot silently broaden a rule`() {
        val path = temp.resolve("typo-rules.json")
        Files.writeString(path, """{"schemaVersion":3,"items":[{"semanticId":"id","locators":[{"kind":"field-initializer","anchor":"value","factors":[{"kind":"method-signature","returnSameAsField":true,"parameterType":["Ljava/lang/String;"]}]}]}]}""")
        assertFailsWith<ValidationException> { MigrationService.readRules(path) }
        Files.writeString(path, """{"schemaVersion":3,"items":[{"semanticId":"id","locators":[{"kind":"string-use","anchor":"value"}],"expectedTarget":"La;"}]}""")
        assertFailsWith<ValidationException> { MigrationService.readRules(path) }
    }

    @Test fun `target progress preserves a confirmed entry across inheritance and a failed rule update`() {
        val f = fixture()
        submit(f, "round1-review.json", listOf(MigrationFixtures.review(f.run)))
        val baseDir = temp.resolve("round1-published")
        MigrationService.publish(f.dir, baseDir)
        val basePath = baseDir.resolve("knowledge.json")
        val base = KnowledgeFiles.read(basePath)
        assertEquals(f.run.knowledge.knowledgeId, base.migrationSourceKnowledgeId)
        val inherited = f.run.copy(runId = "", createdAt = "round2", targetBaseFile = Digests.artifact(basePath), targetBase = base,
            tasks = f.run.tasks.map { task -> if (task.taskId == "item-0") task.copy(inheritedEntry = base.entries.single()) else task })
            .let { it.copy(runId = it.fingerprint()) }
        val inheritedDir = Files.createDirectory(temp.resolve("round2"))
        JsonFiles.writeNew(inheritedDir.resolve("run.json"), inherited)
        val inheritedPage = MigrationService.tasks(inheritedDir, "INHERITED")
        assertEquals(1, inheritedPage.total)
        assertEquals(MigrationExecutionState.INHERITED, inheritedPage.tasks.single().executionState)
        val round2 = temp.resolve("round2-published")
        MigrationService.publish(inheritedDir, round2)
        assertEquals(base.entries, KnowledgeFiles.read(round2.resolve("knowledge.json")).entries)
        assertEquals(Files.readString(baseDir.resolve("mapping.tiny")), Files.readString(round2.resolve("mapping.tiny")))

        val newLocator = Locator("string-use", "intentionally absent")
        val override = MigrationRuleOverride("item-0", listOf(newLocator), f.run.tasks.first().entry.ruleRevision!!.revisionId)
        val rulesPath = temp.resolve("failed-round-rules.json")
        JsonFiles.writeNew(rulesPath, MigrationRulesFile(items = listOf(override)))
        val rule = RuleProofs.revision(listOf(newLocator))
        val failed = inherited.copy(runId = "", rulesFile = Digests.artifact(rulesPath), ruleOverrides = listOf(override),
            tasks = inherited.tasks.map { task -> if (task.taskId == "item-0") task.copy(rule = rule, resolution = RuleProofs.create(f.run.targetApk.sha256, rule, f.run.engineBuildId, emptyList()), inheritedEntry = null) else task })
            .let { it.copy(runId = it.fingerprint()) }
        val failedDir = Files.createDirectory(temp.resolve("failed-round"))
        JsonFiles.writeNew(failedDir.resolve("run.json"), failed)
        assertEquals(TaskState.INVALID, MigrationService.tasks(failedDir, "ALL").tasks.first().state)
        val failedOut = temp.resolve("failed-round-published")
        MigrationService.publish(failedDir, failedOut)
        val preserved = KnowledgeFiles.read(failedOut.resolve("knowledge.json"))
        assertEquals(base.entries, preserved.entries)
        assertEquals(base.unresolved.map { it.entry }, preserved.unresolved.map { it.entry })
        assertEquals(Files.readString(baseDir.resolve("mapping.tiny")), Files.readString(failedOut.resolve("mapping.tiny")))
    }

    @Test fun `target progress cannot be borrowed from another source or target APK`() {
        val f = fixture()
        val base = VersionKnowledge(knowledgeId = "", artifact = f.run.targetApk, entries = emptyList(),
            unresolved = f.run.knowledge.unresolved + f.run.knowledge.entries.map { UnresolvedKnowledge(it, f.run.knowledge.knowledgeId, "waiting", "run") },
            provenance = "migration:test", migrationSourceKnowledgeId = "other-source")
            .let { it.copy(knowledgeId = KnowledgeFiles.id(it)) }
        assertFailsWith<ValidationException> { MigrationService.validateTargetBase(f.run.knowledge, f.run.targetApk, base) }
        val correctSource = base.copy(knowledgeId = "", migrationSourceKnowledgeId = f.run.knowledge.knowledgeId)
            .let { it.copy(knowledgeId = KnowledgeFiles.id(it)) }
        assertFailsWith<ValidationException> { MigrationService.validateTargetBase(f.run.knowledge, f.run.sourceApk, correctSource) }
        MigrationService.validateTargetBase(f.run.knowledge, f.run.targetApk, correctSource)
    }
}
