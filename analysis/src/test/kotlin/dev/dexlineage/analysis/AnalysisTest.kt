package dev.dexlineage.analysis

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class AnalysisTest {
    @TempDir lateinit var temp: Path
    private val inventory = mapOf("La;" to "classes.dex", "Lb;" to "classes.dex", "Lc;" to "classes.dex", "Lfactory;" to "classes.dex")
    private fun apk() = Digests.artifact(temp.resolve("fixture.apk").also { if (!Files.exists(it)) Files.writeString(it, "identity fixture only; no synthetic APK") })
    private fun ref(apk: Artifact, descriptor: String) = ClassRef(apk.sha256, descriptor, "classes.dex")
    private fun fact(apk: Artifact, owner: String, literal: String = "signal", status: MatchStatus = MatchStatus.PASS) =
        MatchFact(ref(apk, owner), status, listOf(FactorResult("anchor", status, "fixture condition")), mapOf("literal" to literal),
            stringUses = listOf(StringUseSite("classes.dex", owner, "$owner->m()V", 1, 2, literal)))
    private fun resolution(apk: Artifact, owners: List<String>, literal: String = "signal", status: MatchStatus = MatchStatus.PASS): Resolution {
        val rule = RuleProofs.revision(listOf(Locator("string-use", literal)))
        return RuleProofs.create(apk.sha256, rule, "test-build", owners.map { fact(apk, it, literal, status) })
    }
    private fun task(apk: Artifact, key: String = "target", owners: List<String> = listOf("La;"), semanticId: String? = null,
                     base: VersionKnowledge? = null, literal: String = "signal"): AnalysisTask {
        val proof = resolution(apk, owners, literal)
        val item = AnalysisRuleItem(key, semanticId, "Component", proof.rule.locators)
        return AnalysisService.makeTask(apk, item, proof.rule, proof, null, base)
    }
    private fun run(tasks: List<AnalysisTask>, apk: Artifact, base: VersionKnowledge? = null, dirName: String = "run"): Pair<Path, AnalysisRun> {
        val dir = temp.resolve(dirName)
        Files.createDirectories(dir)
        val rules = AnalysisRuleFile(items = tasks.map { it.request })
        val rulesPath = temp.resolve("$dirName-rules.json")
        JsonFiles.writeNew(rulesPath, rules)
        val basePath = base?.let { temp.resolve("base/knowledge.json") }
        var r = AnalysisRun(runId = "", engineBuildId = "test-build", apk = apk, rulesFile = Digests.artifact(rulesPath), rules = rules,
            discoveryFile = null, discovery = null, baseFile = basePath?.let(Digests::artifact), baseKnowledge = base,
            classInventory = inventory, tasks = tasks.sortedBy { it.taskId }, scan = ScanStats(4, 1, 1, 1, 0, emptyList()),
            analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "now")
        r = r.copy(runId = r.fingerprint())
        JsonFiles.writeNew(dir.resolve("run.json"), r)
        val refs = tasks.flatMap { AnalysisPolicy.allowedRefs(r, it) }.distinct()
        EvidenceFiles.publish(dir, r.runId, apk, refs, refs.map { DecompiledClass(it.descriptor, "class ${Identities.rawName(it.descriptor)} {}", null, false, emptyList(), 0) })
        return dir to r
    }
    private fun review(run: AnalysisRun, task: AnalysisTask = run.tasks.first(), name: String = "Component", action: ReviewAction = ReviewAction.ACCEPT): AnalysisReview =
        AnalysisReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, action, name, Confidence.HIGH,
            "Read actual owner responsibility", emptyList(), task.resolution!!.candidates.map { Identities.evidenceId(run.runId, it.ref) })
    private fun submit(dir: Path, run: AnalysisRun, filename: String, items: List<AnalysisReview>): AnalysisSubmitResult {
        val file = temp.resolve(filename)
        JsonFiles.writeNew(file, AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256, items = items))
        return AnalysisService.submit(dir, file)
    }
    private fun base(apk: Artifact): VersionKnowledge {
        val dir = temp.resolve("base")
        Files.createDirectories(dir)
        val owner = ref(apk, "La;")
        EvidenceFiles.publish(dir, "base-run", apk, listOf(owner), listOf(DecompiledClass("La;", "class a {}", null, false, emptyList(), 0)))
        val proof = resolution(apk, listOf("La;"), "old-rule")
        val e = EvidenceFiles.read(dir, "base-run", Identities.evidenceId("base-run", owner))
        val portable = KnowledgeEvidence(e.evidenceId, e.ref, e.javaPath, e.javaSha256, e.smaliPath, e.smaliSha256, e.incomplete, e.diagnostics)
        val entry = KnowledgeEntry("stable-id", "Existing", owner, RuleProofs.captures(proof), proof.rule.locators, listOf(portable), "Reviewed previously", "prior", proof.rule, proof)
        return KnowledgeFiles.write(dir, VersionKnowledge(knowledgeId = "", artifact = apk, entries = listOf(entry), unresolved = emptyList(), provenance = "prior"))
    }

    @Test fun `two entities remain invalid despite distinct aliases or rejecting a rival task`() {
        val apk = apk()
        val (dir, run) = run(listOf(task(apk, "first", listOf("La;", "Lb;")), task(apk, "second", listOf("La;", "Lb;"))), apk)
        assertEquals(2, AnalysisService.tasks(dir, "INVALID").total)
        assertEquals(0, AnalysisService.tasks(dir).total)
        assertFailsWith<ValidationException> { submit(dir, run, "bad.json", listOf(review(run, run.tasks[0], "One"), review(run, run.tasks[1], "Two"))) }
        submit(dir, run, "reject.json", listOf(review(run, run.tasks[1], "Two", ReviewAction.REJECT)))
        assertFailsWith<ValidationException> { submit(dir, run, "bad-alone.json", listOf(review(run, run.tasks[0], "One"))) }
        assertEquals(2, AnalysisService.tasks(dir, "INVALID").total)
        assertEquals(0, AnalysisService.publish(dir, temp.resolve("invalid-output")).confirmed)
    }

    @Test fun `unique result needs review and old resolution cannot authorize a new rule`() {
        val apk = apk()
        val (dir, run) = run(listOf(task(apk)), apk)
        assertEquals(1, AnalysisService.tasks(dir).total)
        assertEquals(0, AnalysisService.publish(dir, temp.resolve("unreviewed")).confirmed)
        assertFailsWith<ValidationException> { submit(dir, run, "stale-proof.json", listOf(review(run).copy(resolutionId = "old"))) }
        assertFailsWith<ValidationException> { submit(dir, run, "stale-rule.json", listOf(review(run).copy(ruleRevisionId = "old"))) }
        assertFailsWith<ValidationException> { submit(dir, run, "wrong-evidence.json", listOf(review(run).copy(evidenceIds = listOf("bad")))) }
    }

    @Test fun `plain string rule needs owner evidence but no logger factory`() {
        val apk = apk()
        val (dir, run) = run(listOf(task(apk)), apk)
        submit(dir, run, "review.json", listOf(review(run, name = "CorrectedName")))
        val published = AnalysisService.publish(dir, temp.resolve("output"))
        val entry = KnowledgeFiles.read(Path.of(published.knowledgePath)).entries.single()
        assertEquals("CorrectedName", entry.name)
        assertEquals("signal", entry.captures["literal"])
        assertEquals(run.tasks.single().rule, entry.ruleRevision)
        assertEquals(run.tasks.single().resolution, entry.resolution)
    }

    @Test fun `field initializer naming requires factory semantics as well as owner evidence`() {
        val apk = apk()
        val owner = ref(apk, "La;")
        val locator = Locator("field-initializer", "signal", captures = listOf(CaptureSpec("component", 1)))
        val rule = RuleProofs.revision(listOf(locator))
        val binding = FieldBinding(owner, "logger", "Lfactory;", 0x1a, "<clinit>()V",
            CallFact("Lfactory;", "create", listOf("Ljava/lang/String;", "Ljava/lang/String;"), "Lfactory;", "STATIC", listOf("scope", "signal"), 4), "La;")
        val proof = RuleProofs.create(apk.sha256, rule, "test-build", listOf(MatchFact(owner, MatchStatus.PASS,
            listOf(FactorResult("anchor", MatchStatus.PASS, "same call")), mapOf("component" to "signal"), binding)))
        val input = AnalysisRuleItem("logger", proposedName = "Component", locators = rule.locators)
        val target = AnalysisService.makeTask(apk, input, rule, proof, null, null)
        val (dir, run) = run(listOf(target), apk)
        val ownerOnly = review(run)
        submit(dir, run, "owner-only.json", listOf(ownerOnly))
        assertEquals("owner_or_factory_evidence_missing", AnalysisService.tasks(dir, "DEFERRED").items.single().reason)
        val prior = ReviewStore.latest(dir, run.runId).getValue(target.taskId).revisionId
        val both = ownerOnly.copy(evidenceIds = ownerOnly.evidenceIds + Identities.evidenceId(run.runId, ref(apk, "Lfactory;")), supersedes = prior)
        submit(dir, run, "with-factory.json", listOf(both))
        assertEquals(1, AnalysisService.tasks(dir, "ACCEPTED").total)
    }

    @Test fun `discovery owner is an assertion after global lookup and cannot hide outside competitors`() {
        val apk = apk()
        val profile = AnalysisProfile(id = "sample", discovery = Locator("string-use", "scope"))
        val lead = DiscoveryLead("lead", ref(apk, "La;"), "Component", mapOf("literal" to "scope"), listOf(fact(apk, "La;", "scope")))
        val discovery = AnalysisDiscovery(discoveryId = "unused", engineBuildId = "test-build", apk = apk, profileSource = apk, profile = profile,
            classInventory = inventory, leads = listOf(lead), matches = lead.matches, scan = ScanStats(4, 1, 1, 1, 0, emptyList()),
            matchCounts = emptyMap(), conditionCounts = emptyMap(), analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "now")
        val onlyOther = resolution(apk, listOf("Lb;"))
        val input = AnalysisRuleItem("lead", locators = onlyOther.rule.locators, discoveryKey = "lead")
        val mismatch = AnalysisService.makeTask(apk, input, onlyOther.rule, onlyOther, discovery, null)
        assertEquals("discovery_owner_mismatch", mismatch.invalidReason)
        val outside = resolution(apk, listOf("La;", "Lb;"))
        val ambiguous = AnalysisService.makeTask(apk, input, outside.rule, outside, discovery, null)
        assertEquals("resolution_ambiguous", ambiguous.invalidReason)
    }

    @Test fun `scope discovery and optional template do not pretend to confirm identities`() {
        val apk = apk()
        val p = AnalysisProfile(id = "scope", discovery = Locator("string-use", "scope"), nameCapture = "literal")
        val path = temp.resolve("profile.json")
        JsonFiles.writeNew(path, p)
        assertNull(AnalysisService.readProfile(path).locatorTemplate)
        assertEquals(2, AnalysisService.createLeads(apk, p, listOf(fact(apk, "La;", "scope"), fact(apk, "Lb;", "scope"))).size)
        val draft = temp.resolve("draft-name.json")
        JsonFiles.writeNew(draft, AnalysisRuleFile(items = listOf(AnalysisRuleItem("draft", proposedName = "raw component / hint", locators = listOf(Locator("string-use", "scope"))))))
        assertEquals("raw component / hint", AnalysisService.readRules(draft).items.single().proposedName)
    }

    @Test fun `target descriptor is not an accepted rule input`() {
        val p = temp.resolve("forged.json")
        Files.writeString(p, """{"schemaVersion":4,"kind":"analysis-rules","items":[{"key":"x","expectedOwner":"La;","locators":[{"kind":"string-use","anchor":"x"}]}]}""")
        assertFailsWith<ValidationException> { AnalysisService.readRules(p) }
    }

    @Test fun `unknown nested rule fields and misspelled profile options do not weaken constraints`() {
        val rules = temp.resolve("typo-rules.json")
        Files.writeString(rules, """{"schemaVersion":4,"kind":"analysis-rules","items":[{"key":"x","locators":[{"kind":"field-initializer","anchor":"x","factors":[{"kind":"method-signature","returnSameAsField":true,"parameterType":["Ljava/lang/String;"]}]}]}]}""")
        assertFailsWith<ValidationException> { AnalysisService.readRules(rules) }
        val profile = temp.resolve("typo-profile.json")
        Files.writeString(profile, """{"schemaVersion":4,"id":"x","discovery":{"kind":"string-use","anchor":"x"},"locator_template":{}}""")
        assertFailsWith<ValidationException> { AnalysisService.readProfile(profile) }
    }

    @Test fun `base identity reused and failed replacement leaves prior knowledge intact`() {
        val apk = apk()
        val base = base(apk)
        val update = task(apk, base = base, literal = "new-rule")
        assertEquals("stable-id", update.semanticId)
        val failed = task(apk, "failed", owners = emptyList(), semanticId = "stable-id", base = base)
        val (dir, run) = run(listOf(failed), apk, base)
        assertEquals(1, AnalysisService.tasks(dir, "INVALID").total)
        val published = AnalysisService.publish(dir, temp.resolve("kept"))
        val result = KnowledgeFiles.read(Path.of(published.knowledgePath))
        assertEquals(base.entries, result.entries)
        assertEquals(base.knowledgeId, result.parentKnowledgeId)
        assertFailsWith<ValidationException> { submit(dir, run, "invalid-accept.json", listOf(review(run))) }
    }

    @Test fun `unchanged base confirmation is inherited without creating a new review`() {
        val apk = apk()
        val base = base(apk)
        val entry = base.entries.single()
        val input = AnalysisRuleItem("existing", semanticId = entry.semanticId, proposedName = entry.name, locators = entry.locators)
        val target = AnalysisService.makeTask(apk, input, entry.ruleRevision!!, entry.resolution, null, base, inherited = true)
        val (dir, current) = run(listOf(target), apk, base)
        assertEquals(1, AnalysisService.tasks(dir, "INHERITED").total)
        assertEquals(0, AnalysisService.tasks(dir).total)
        val published = AnalysisService.publish(dir, temp.resolve("inherited"))
        assertEquals(0, published.acceptedUpdates)
        assertEquals(base.entries, KnowledgeFiles.read(Path.of(published.knowledgePath)).entries)
        assertFailsWith<ValidationException> { submit(dir, current, "unnecessary.json", listOf(review(current))) }
    }

    @Test fun `new rule replaces old rule and existing semantic id cannot move to another entity`() {
        val apk = apk()
        val base = base(apk)
        val updateTask = task(apk, semanticId = "stable-id", base = base, literal = "replacement")
        val (dir, run) = run(listOf(updateTask), apk, base)
        submit(dir, run, "replace.json", listOf(review(run, name = "Existing")))
        val entry = KnowledgeFiles.read(Path.of(AnalysisService.publish(dir, temp.resolve("replacement")).knowledgePath)).entries.single()
        assertEquals("stable-id", entry.semanticId)
        assertEquals(listOf(Locator("string-use", "replacement")), entry.locators)
        assertNotEquals(base.entries.single().ruleRevision, entry.ruleRevision)
        assertEquals("existing_binding_changed", task(apk, "wrong-owner", listOf("Lb;"), "stable-id", base).invalidReason)
    }

    @Test fun `same APK pending retry is explicit and cross APK pending is not inferred`() {
        val apk = apk()
        val entry = base(apk).entries.single()
        val pending = VersionKnowledge(knowledgeId = "pending", artifact = apk, entries = emptyList(),
            unresolved = listOf(UnresolvedKnowledge(entry, "prior", "ambiguous", "prior-run")), provenance = "pending")
        assertEquals("pending_requires_explicit_semantic_id", task(apk, base = pending).invalidReason)
        assertEquals("stable-id", task(apk, semanticId = "stable-id", base = pending).semanticId)
        val foreign = pending.copy(unresolved = listOf(pending.unresolved.single().copy(entry = entry.copy(binding = entry.binding.copy(apkSha256 = "older")))))
        assertNull(task(apk, base = foreign).existingEntry)
        val occupied = pending.copy(entries = listOf(entry.copy(semanticId = "other-confirmed-id")))
        assertEquals("semantic_identity_conflict", task(apk, semanticId = "stable-id", base = occupied).invalidReason)
    }

    @Test fun `conflicting new updates defer together while untouched base is preserved`() {
        val apk = apk()
        val base = base(apk)
        val (dir, run) = run(listOf(task(apk, "new-one", listOf("Lb;"), base = base), task(apk, "new-two", listOf("Lc;"), base = base)), apk, base)
        submit(dir, run, "conflicts.json", run.tasks.map { review(run, it, "Existing") })
        assertEquals(2, AnalysisService.tasks(dir, "DEFERRED").total)
        val result = KnowledgeFiles.read(Path.of(AnalysisService.publish(dir, temp.resolve("conflict-output")).knowledgePath))
        assertEquals(base.entries, result.entries)
    }

    @Test fun `same entity multiple task updates conflict regardless of alias`() {
        val apk = apk()
        val (dir, run) = run(listOf(task(apk, "one"), task(apk, "two")), apk)
        submit(dir, run, "two-updates.json", run.tasks.mapIndexed { i, t -> review(run, t, "Component$i") })
        assertEquals(2, AnalysisService.tasks(dir, "DEFERRED").total)
        assertEquals(0, AnalysisService.publish(dir, temp.resolve("no-winner")).confirmed)
    }

    @Test fun `idempotent submit explicit revisions restore historical publication without rolling back queue`() {
        val apk = apk()
        val (dir, run) = run(listOf(task(apk)), apk)
        val accepted = review(run)
        val first = submit(dir, run, "accepted.json", listOf(accepted))
        assertEquals(first.revisions, AnalysisService.submit(dir, temp.resolve("accepted.json")).revisions)
        val initial = AnalysisService.publish(dir, temp.resolve("published"))
        assertFailsWith<ValidationException> { submit(dir, run, "stale.json", listOf(accepted.copy(action = ReviewAction.REJECT))) }
        submit(dir, run, "rejected.json", listOf(accepted.copy(action = ReviewAction.REJECT, supersedes = first.revisions.getValue(accepted.taskId))))
        assertEquals(1, AnalysisService.tasks(dir, "REJECTED").total)
        val replay = AnalysisService.publish(dir, temp.resolve("replay"), Path.of(initial.reportPath))
        assertEquals(initial.knowledgeId, replay.knowledgeId)
        assertEquals(Files.readString(Path.of(initial.mappingPath)), Files.readString(Path.of(replay.mappingPath)))
        assertEquals(1, AnalysisService.tasks(dir, "REJECTED").total)
    }

    @Test fun `batch with later stale supersedes never partially saves`() {
        val apk = apk()
        val (dir, run) = run(listOf(task(apk, "one"), task(apk, "two", listOf("Lb;"))), apk)
        val existing = review(run, run.tasks[1], "Second", ReviewAction.DEFER)
        submit(dir, run, "first-defer.json", listOf(existing))
        assertFailsWith<ValidationException> { submit(dir, run, "partial.json", listOf(review(run, run.tasks[0], "First"), existing.copy(action = ReviewAction.ACCEPT))) }
        assertEquals(setOf("two"), ReviewStore.latest(dir, run.runId).keys)
    }

    @Test fun `partial code requires acknowledgment but does not forbid a supported name`() {
        val apk = apk()
        val (_, run) = run(listOf(task(apk)), apk)
        val r = review(run)
        val owner = run.tasks.single().resolution!!.uniqueRef!!
        val record = EvidenceRecord(evidenceId = r.evidenceIds.single(), runId = run.runId, ref = owner, javaPath = "unused", javaSha256 = "unused",
            smaliPath = "unused", smaliSha256 = "unused", incomplete = true, diagnostics = listOf("placeholder"), elapsedMillis = 0)
        assertEquals(TaskState.DEFERRED, AnalysisPolicy.decide(run, mapOf(r.taskId to r), mapOf(record.evidenceId to record)).single().state)
        assertEquals(TaskState.ACCEPTED, AnalysisPolicy.decide(run, mapOf(r.taskId to r.copy(unverified = listOf("Unrelated method is incomplete"))), mapOf(record.evidenceId to record)).single().state)
    }
}
