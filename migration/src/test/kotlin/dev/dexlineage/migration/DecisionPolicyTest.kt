package dev.dexlineage.migration

import com.google.gson.JsonNull
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import kotlin.test.*

internal object MigrationFixtures {
    val oldSha = "a".repeat(64)
    val newSha = "b".repeat(64)
    val stats = ScanStats(3, 3, 10, 3, 1, emptyList())
    fun proof(ref: ClassRef, locators: List<Locator>, status: MatchStatus = MatchStatus.PASS): Resolution {
        val rule = RuleProofs.revision(locators)
        val match = MatchFact(ref, status, listOf(FactorResult("anchor", status, "Fixture fact")), mapOf("literal" to locators.first().anchor),
            stringUses = listOf(StringUseSite(ref.dexEntry, ref.descriptor, "${ref.descriptor}->a()V", 0, 0, locators.first().anchor)))
        return RuleProofs.create(ref.apkSha256, rule, "fixture-engine", listOf(match))
    }
    fun task(id: String = "cache", source: String = "La;", targets: List<String> = listOf("Lx;"), name: String = "ProviderCache"): MigrationTask {
        val oldRef = ClassRef(oldSha, source, "classes.dex")
        val locators = listOf(Locator("string-use", "captured component"))
        val prior = proof(oldRef, locators)
        val entry = KnowledgeEntry(id, name, oldRef, mapOf("literal" to "captured component"), locators, emptyList(), "Previously confirmed responsibility", "analysis:previous", prior.rule, prior)
        val facts = targets.flatMap { descriptor -> proof(ClassRef(newSha, descriptor, "classes2.dex"), locators).matches }
        return MigrationTask(id, entry, RuleProofs.create(newSha, prior.rule, "fixture-engine", facts))
    }
    fun run(tasks: List<MigrationTask> = listOf(task()), extra: List<String> = emptyList()): MigrationRun = MigrationRun(
        runId = "example-run", knowledgeFile = Artifact("knowledge.json", "c".repeat(64)),
        knowledge = VersionKnowledge(knowledgeId = "old-knowledge", artifact = Artifact("old.apk", oldSha), entries = tasks.map { it.entry }, unresolved = emptyList(), provenance = "test"),
        sourceApk = Artifact("old.apk", oldSha), targetApk = Artifact("new.apk", newSha), minConfidence = Confidence.HIGH, tasks = tasks,
        sourceInventory = tasks.associate { it.entry.binding.descriptor to "classes.dex" },
        targetInventory = (tasks.flatMap { it.candidates.map { c -> c.ref.descriptor } } + extra).associateWith { "classes2.dex" },
        sourceScan = stats, targetScan = stats, analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "", engineBuildId = "fixture-engine")
    fun evidence(run: MigrationRun, ref: ClassRef, incomplete: Boolean = false): EvidenceRecord {
        val id = Identities.evidenceId(run.runId, ref)
        return EvidenceRecord(evidenceId = id, runId = run.runId, ref = ref, javaPath = "evidence/$id/code.java", javaSha256 = "d".repeat(64),
            smaliPath = null, smaliSha256 = null, incomplete = incomplete, diagnostics = emptyList(), elapsedMillis = 0)
    }
    fun evidence(run: MigrationRun): Map<String, EvidenceRecord> = run.tasks.flatMap { task -> listOf(task.entry.binding) + task.candidates.map { it.ref } }
        .map { evidence(run, it) }.associateBy { it.evidenceId }
    fun review(run: MigrationRun, task: MigrationTask = run.tasks.first()): MigrationReview =
        MigrationReview(task.taskId, task.resolution.resolutionId, task.resolution.rule.revisionId, ReviewAction.ACCEPT, Confidence.HIGH, true,
            "Source and target retain the provider cache responsibility", listOf("Constructor dependencies changed"), emptyList(),
            (listOf(task.entry.binding) + listOfNotNull(task.resolution.uniqueRef)).map { Identities.evidenceId(run.runId, it) })
    fun decide(run: MigrationRun, reviews: List<MigrationReview> = run.tasks.map { review(run, it) }, evidence: Map<String, EvidenceRecord> = evidence(run)) =
        DecisionPolicy.decide(run, reviews.associate { it.taskId to ("revision:${it.taskId}" to it) }, evidence)
}

class DecisionPolicyTest {
    @Test fun `unique candidate still requires review and old plus new evidence`() {
        val run = MigrationFixtures.run()
        assertEquals(TaskState.UNREVIEWED, MigrationFixtures.decide(run, emptyList()).single().state)
        val review = MigrationFixtures.review(run)
        for (ids in listOf(emptyList(), review.evidenceIds.take(1), review.evidenceIds.takeLast(1))) {
            val decision = MigrationFixtures.decide(run, listOf(review.copy(evidenceIds = ids))).single()
            assertEquals(TaskState.DEFERRED, decision.state)
            assertNull(decision.target)
        }
        assertEquals(TaskState.ACCEPTED, MigrationFixtures.decide(run).single().state)
    }
    @Test fun `multiple candidates are invalid even with HIGH review and no review is required`() {
        val run = MigrationFixtures.run(listOf(MigrationFixtures.task(targets = listOf("Lx;", "Ly;"))))
        assertEquals(TaskState.INVALID, MigrationFixtures.decide(run, emptyList()).single().state)
        assertFailsWith<ValidationException> { MigrationFixtures.decide(run) }
        val deferred = MigrationFixtures.review(run).copy(action = ReviewAction.DEFER)
        assertEquals(TaskState.INVALID, MigrationFixtures.decide(run, listOf(deferred)).single().state)
    }
    @Test fun `unknown facts and a second unknown entity cannot be accepted`() {
        val original = MigrationFixtures.task()
        val unknown = MigrationFixtures.proof(original.candidates.single().ref, original.entry.locators, MatchStatus.UNKNOWN)
        for (facts in listOf(unknown.matches, original.matches + MigrationFixtures.proof(ClassRef(MigrationFixtures.newSha, "Ly;", "classes2.dex"), original.entry.locators, MatchStatus.UNKNOWN).matches)) {
            val task = original.copy(resolution = RuleProofs.create(MigrationFixtures.newSha, original.resolution.rule, "fixture-engine", facts))
            val run = MigrationFixtures.run(listOf(task))
            assertEquals(TaskState.INVALID, MigrationFixtures.decide(run, emptyList()).single().state)
            assertFailsWith<ValidationException> { MigrationFixtures.decide(run) }
        }
    }
    @Test fun `foreign target and evidence bindings are rejected even for low confidence`() {
        val run = MigrationFixtures.run()
        val review = MigrationFixtures.review(run).copy(level = Confidence.LOW)
        assertFailsWith<ValidationException> { MigrationFixtures.decide(run, listOf(review.copy(resolutionId = "other-execution"))) }
        for (ref in listOf(ClassRef(MigrationFixtures.oldSha, "Lx;", "classes2.dex"), ClassRef(MigrationFixtures.newSha, "Lx;", "wrong.dex"))) {
            val forged = MigrationFixtures.evidence(run, ref)
            assertFailsWith<ValidationException> { MigrationFixtures.decide(run, listOf(review.copy(evidenceIds = listOf(forged.evidenceId))), MigrationFixtures.evidence(run) + (forged.evidenceId to forged)) }
        }
        val evidence = MigrationFixtures.evidence(run).mapValues { (_, e) -> e.copy(runId = "foreign") }
        assertFailsWith<ValidationException> { MigrationFixtures.decide(run, listOf(review), evidence) }
    }
    @Test fun `incomplete decompilation is visible and needs bounded review acknowledgement`() {
        val run = MigrationFixtures.run()
        val evidence = MigrationFixtures.evidence(run).mapValues { (_, e) -> e.copy(incomplete = true) }
        val review = MigrationFixtures.review(run)
        assertEquals("incomplete_evidence_not_acknowledged", MigrationFixtures.decide(run, listOf(review), evidence).single().reason)
        assertEquals(TaskState.ACCEPTED, MigrationFixtures.decide(run, listOf(review.copy(unverified = listOf("One unrelated method remains a placeholder"))), evidence).single().state)
    }
    @Test fun `whole conflict group defers while an independent task can publish`() {
        for (duplicateTarget in listOf(true, false)) {
            val tasks = listOf(MigrationFixtures.task(), MigrationFixtures.task("other", "Lb;", listOf(if (duplicateTarget) "Lx;" else "Ly;"), if (duplicateTarget) "OtherCache" else "ProviderCache"),
                MigrationFixtures.task("independent", "Lc;", listOf("Lz;"), "IndependentCache"))
            val decisions = MigrationFixtures.decide(MigrationFixtures.run(tasks)).associateBy { it.taskId }
            assertEquals(TaskState.DEFERRED, decisions.getValue("cache").state)
            assertEquals(TaskState.DEFERRED, decisions.getValue("other").state)
            assertNull(decisions.getValue("cache").target)
            assertEquals(TaskState.ACCEPTED, decisions.getValue("independent").state)
        }
    }
    @Test fun `remaining raw names participate in namespace validation`() {
        val run = MigrationFixtures.run(extra = listOf("LProviderCache;"))
        assertEquals("name_conflict", MigrationFixtures.decide(run).single().reason)
    }
    @Test fun `saved review replay is deterministic and captured locator is not renamed`() {
        val run = MigrationFixtures.run()
        val review = MigrationFixtures.review(run)
        val replay = JsonFiles.gson.fromJson(JsonFiles.encode(review), MigrationReview::class.java)
        assertEquals(MigrationFixtures.decide(run, listOf(review)), MigrationFixtures.decide(run, listOf(replay)))
        assertEquals("captured component", run.tasks.single().entry.locators.single().anchor)
        assertNotEquals(run.tasks.single().entry.name, run.tasks.single().entry.locators.single().anchor)
    }
    @Test fun `malformed mandatory review fields and null list elements are errors`() {
        val run = MigrationFixtures.run()
        for (field in listOf("taskId", "action", "level", "identityReason", "changes", "unverified", "evidenceIds", "resolutionId", "ruleRevisionId")) {
            val json = JsonFiles.gson.toJsonTree(MigrationFixtures.review(run)).asJsonObject
            json.add(field, JsonNull.INSTANCE)
            val malformed = JsonFiles.gson.fromJson(json, MigrationReview::class.java)
            assertFailsWith<ValidationException> { DecisionPolicy.validateReview(run, run.tasks.single(), malformed, MigrationFixtures.evidence(run)) }
        }
    }
    @Test fun `frozen confidence threshold and semantic applicability constrain export`() {
        val run = MigrationFixtures.run()
        val review = MigrationFixtures.review(run)
        assertEquals("confidence_below_threshold", MigrationFixtures.decide(run, listOf(review.copy(level = Confidence.MEDIUM))).single().reason)
        assertEquals(TaskState.ACCEPTED, MigrationFixtures.decide(run.copy(minConfidence = Confidence.MEDIUM), listOf(review.copy(level = Confidence.MEDIUM))).single().state)
        assertEquals("name_no_longer_applies", MigrationFixtures.decide(run, listOf(review.copy(nameStillApplies = false))).single().reason)
        assertNotEquals(run.fingerprint(), run.copy(minConfidence = Confidence.LOW).fingerprint())
    }
    @Test fun `overrides replace whole rule set without broadening semantic scope`() {
        val run = MigrationFixtures.run()
        val previous = run.tasks.single().entry.ruleRevision!!
        val newLocator = Locator("string-use", "target-only literal")
        val changed = MigrationService.effectiveRules(run.knowledge, listOf(MigrationRuleOverride("cache", listOf(newLocator), previous.revisionId)))
        assertEquals(listOf(newLocator), changed.getValue("cache").locators)
        assertEquals(previous, MigrationService.effectiveRules(run.knowledge, emptyList()).getValue("cache"))
        assertFailsWith<ValidationException> { MigrationService.effectiveRules(run.knowledge, listOf(MigrationRuleOverride("new-target", listOf(newLocator)))) }
        assertFailsWith<ValidationException> { MigrationService.effectiveRules(run.knowledge, listOf(MigrationRuleOverride("cache", listOf(newLocator), "wrong"))) }
        val duplicate = MigrationRuleOverride("cache", listOf(newLocator))
        assertFailsWith<ValidationException> { MigrationService.effectiveRules(run.knowledge, listOf(duplicate, duplicate)) }
    }
    @Test fun `target-only rule cannot accept a review bound to the source rule`() {
        val task = MigrationFixtures.task()
        val changedRule = RuleProofs.revision(listOf(Locator("string-use", "new-target-feature")))
        val changedProof = MigrationFixtures.proof(task.resolution.uniqueRef!!, changedRule.locators)
        val run = MigrationFixtures.run(listOf(task.copy(resolution = changedProof)))
        val review = MigrationFixtures.review(run).copy(ruleRevisionId = task.resolution.rule.revisionId)
        assertFailsWith<ValidationException> { MigrationFixtures.decide(run, listOf(review)) }
    }
}
