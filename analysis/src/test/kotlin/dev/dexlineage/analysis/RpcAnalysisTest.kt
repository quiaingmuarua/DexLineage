package dev.dexlineage.analysis

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class RpcAnalysisTest {
    @TempDir lateinit var temp: Path
    private val inventory = mapOf("La;" to "classes.dex", "Lb;" to "classes.dex", "Lcaller;" to "classes.dex")
    private fun apk(name: String = "fixture") = Digests.artifact(temp.resolve("$name.apk").also {
        if (!Files.exists(it)) Files.writeString(it, "identity-only protocol fixture $name")
    })
    private fun ref(apk: Artifact, descriptor: String) = ClassRef(apk.sha256, descriptor, "classes.dex")
    private fun fact(apk: Artifact, descriptor: String, literal: String = "fresh") = MatchFact(ref(apk, descriptor), MatchStatus.PASS,
        listOf(FactorResult("anchor", MatchStatus.PASS, "protocol fixture")), mapOf("literal" to literal))
    private fun proof(apk: Artifact, descriptors: List<String>, literal: String = "fresh"): Resolution {
        val rule = RuleProofs.revision(listOf(Locator("string-use", literal)))
        return RuleProofs.create(apk.sha256, rule, "test-build", descriptors.map { fact(apk, it, literal) })
    }
    private fun reference(apk: Artifact, folder: String, ids: List<Pair<String, String>> = listOf("La;" to "migrated-id", "Lb;" to "unselected-id")): IdentityReference {
        val out = temp.resolve(folder); Files.createDirectories(out)
        val entries = ids.map { (descriptor, id) ->
            val binding = ref(apk, descriptor)
            val p = proof(apk, listOf(descriptor), "old-$id")
            EvidenceFiles.publish(out, "old-$id", apk, listOf(binding), listOf(DecompiledClass(descriptor, "class ${Identities.rawName(descriptor)} {}", null, false, emptyList(), 0)))
            val record = EvidenceFiles.read(out, "old-$id", Identities.evidenceId("old-$id", binding))
            val evidence = KnowledgeEvidence(record.evidenceId, record.ref, record.javaPath, record.javaSha256,
                record.smaliPath, record.smaliSha256, record.incomplete, record.diagnostics)
            KnowledgeEntry(id, "Canonical${Identities.rawName(descriptor).uppercase()}", binding, RuleProofs.captures(p), p.rule.locators,
                listOf(evidence), "Previously reviewed", "fixture-old", p.rule, p)
        }
        val k = KnowledgeFiles.write(out, VersionKnowledge(knowledgeId = "", artifact = apk, entries = entries,
            unresolved = emptyList(), provenance = "fixture-reference"))
        MappingOutput.write(out.resolve("mapping.tiny"), entries.map { AcceptedRename(it.binding.descriptor, it.name) })
        JsonFiles.writeNew(out.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "knowledgeId" to k.knowledgeId))
        return IdentityReferences.load(listOf(out.resolve("knowledge.json")), apk, null)!!.single()
    }
    private fun task(apk: Artifact, references: List<IdentityReference>, descriptors: List<String> = listOf("La;"), explicitId: String? = null): AnalysisTask {
        val p = proof(apk, descriptors)
        val item = AnalysisRuleItem("target", semanticId = explicitId, proposedName = "RpcRequest", locators = p.rule.locators)
        return AnalysisService.makeTask(apk, item, p.rule, p, null, null, references = references)
    }
    private fun run(apk: Artifact, task: AnalysisTask, references: List<IdentityReference>): Pair<Path, AnalysisRun> {
        val dir = temp.resolve("run"); Files.createDirectories(dir)
        val rules = AnalysisRuleFile(items = listOf(task.request))
        val rulesPath = temp.resolve("rules.json"); JsonFiles.writeNew(rulesPath, rules)
        var run = AnalysisRun(runId = "", engineBuildId = "test-build", apk = apk, rulesFile = Digests.artifact(rulesPath), rules = rules,
            discoveryFile = null, discovery = null, baseFile = null, baseKnowledge = null, classInventory = inventory, tasks = listOf(task),
            scan = ScanStats(3, 1, 2, 1, 0, emptyList()), analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "fixture", identityReferences = references)
        run = run.copy(runId = run.fingerprint())
        JsonFiles.writeNew(dir.resolve("run.json"), run)
        val refs = AnalysisPolicy.allowedRefs(run, task).toList()
        EvidenceFiles.publish(dir, run.runId, apk, refs, refs.map { DecompiledClass(it.descriptor, "class ${Identities.rawName(it.descriptor)} {}", null, false, emptyList(), 0) })
        return dir to run
    }
    private fun review(run: AnalysisRun) = AnalysisReview("target", run.tasks.single().resolution!!.resolutionId,
        run.tasks.single().rule.revisionId, ReviewAction.ACCEPT, "CanonicalA", Confidence.HIGH,
        "Fresh owner evidence confirms the existing semantic name", evidenceIds = listOf(Identities.evidenceId(run.runId, run.tasks.single().resolution!!.uniqueRef!!)))

    @Test fun `RPC drafts group by Proto and retain every role and unknown fact regardless of review scope`() {
        val apk = apk()
        val profile = AnalysisProfile(id = "rpc", strategy = StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "factory")),
            rpcDrafts = RpcDraftOptions(reviewServices = listOf("fixture.Group")))
        fun relation(service: String, rpc: String, role: String, status: MatchStatus = MatchStatus.PASS) = MatchFact(ref(apk, "La;"), status,
            listOf(FactorResult("rpc", status, "same construction")), mapOf("service" to service, "rpc" to rpc, "role" to role), relatedRefs = listOf(ref(apk, "Lcaller;")))
        val facts = listOf(relation("fixture.Group", "Read", "request"), relation("fixture.Group", "Read", "response"),
            relation("fixture.Other", "Write", "request"), relation("fixture.Other", "Write", "request", MatchStatus.UNKNOWN))
        val lead = AnalysisService.createLeads(apk, profile, facts).single()
        assertEquals(ref(apk, "La;"), lead.owner)
        assertEquals(4, lead.matches.size)
        assertNull(lead.suggestedName, "A shared Proto must not be arbitrarily named after one RPC")
        val item = RpcAnalysis.drafts(profile, listOf(lead)).single()
        assertEquals(3, item.strategy!!.parameters.getAsJsonArray("selectors").size())
        assertEquals("grpc-java.rpc-message", item.strategy.strategyId)
        val rule = RuleProofs.revision(emptyList(), item.strategy)
        val t = AnalysisTask(item.key, item, rule, null, lead.owner, null, null, null)
        assertTrue(RpcAnalysis.matchesServices(t, setOf("fixture.Other")))
        assertFalse(RpcAnalysis.matchesServices(t, setOf("fixture.OtherExtra")))
        assertFalse(lead.captures.containsKey("suggestedName"))
    }

    @Test fun `only a unique result adopts reference identity and a fresh review is required`() {
        val apk = apk(); val reference = reference(apk, "reference")
        val t = task(apk, listOf(reference))
        assertEquals("migrated-id", t.semanticId)
        assertEquals(reference.knowledge.knowledgeId, t.identitySourceKnowledgeId)
        assertEquals(AnalysisExecutionState.EXECUTED, t.executionState)
        val (dir, run) = run(apk, t, listOf(reference))
        val withoutReview = temp.resolve("unreviewed")
        AnalysisService.publish(dir, withoutReview)
        assertTrue(KnowledgeFiles.read(withoutReview.resolve("knowledge.json")).entries.isEmpty())
        val evidence = EvidenceFiles.available(dir, run.runId).associateBy { it.evidenceId }
        assertFailsWith<ValidationException> { AnalysisPolicy.validateReview(run, t, review(run).copy(name = "RpcRequest"), evidence) }
        assertFailsWith<ValidationException> { AnalysisPolicy.validateReview(run, t, review(run).copy(resolutionId = reference.knowledge.entries.first().resolution!!.resolutionId), evidence) }
        val reviews = temp.resolve("review.json")
        JsonFiles.writeNew(reviews, AnalysisReviewBatch(runId = run.runId, apkSha256 = apk.sha256, items = listOf(review(run))))
        AnalysisService.submit(dir, reviews)
        val published = temp.resolve("published"); AnalysisService.publish(dir, published)
        // Moving the external package demonstrates that the published package is independently consumable.
        Files.move(Path.of(reference.file.path).parent, temp.resolve("reference-away"))
        val entry = KnowledgeFiles.read(published.resolve("knowledge.json")).entries.single()
        assertEquals("migrated-id", entry.semanticId)
        assertEquals("CanonicalA", entry.name)
        assertEquals(t.resolution, entry.resolution)
        assertNotEquals(reference.knowledge.entries.first().resolution, entry.resolution)
        assertEquals(2, Files.readAllLines(published.resolve("mapping.tiny")).size, "Unselected referenced classes must not be copied")
    }

    @Test fun `ambiguous candidates cannot borrow an existing identity or become unique through references`() {
        val apk = apk(); val reference = reference(apk, "reference")
        val t = task(apk, listOf(reference), listOf("La;", "Lb;"))
        assertEquals(ResolutionStatus.AMBIGUOUS, t.resolution!!.status)
        assertEquals(2, t.resolution.candidates.size)
        assertNull(t.existingEntry)
        assertNull(t.semanticId)
        assertNull(t.identitySourceKnowledgeId)
        val mismatched = task(apk, listOf(reference), listOf("Lb;"), "migrated-id")
        assertEquals("existing_binding_changed", mismatched.invalidReason)
        assertEquals(ref(apk, "Lb;"), mismatched.resolution!!.uniqueRef)
    }

    @Test fun `reference identity conflicts and wrong APKs are rejected`() {
        val apk = apk(); val first = reference(apk, "first", listOf("La;" to "old-id"))
        val second = reference(apk, "second", listOf("La;" to "new-id"))
        assertFailsWith<ValidationException> { IdentityReferences.load(listOf(Path.of(first.file.path), Path.of(second.file.path)), apk, null) }
        val reusedId = reference(apk, "third", listOf("Lb;" to "old-id"))
        assertFailsWith<ValidationException> { IdentityReferences.load(listOf(Path.of(first.file.path), Path.of(reusedId.file.path)), apk, null) }
        assertFailsWith<ValidationException> { IdentityReferences.load(listOf(Path.of(first.file.path)), apk("other"), null) }
    }

    @Test fun `same APK pending identity cannot be reclaimed with a different reference ID`() {
        val apk = apk()
        val prior = reference(apk, "prior", listOf("La;" to "pending-id"))
        val external = reference(apk, "external", listOf("La;" to "other-id"))
        val pending = VersionKnowledge(knowledgeId = "fixture-pending", artifact = apk, entries = emptyList(),
            unresolved = listOf(UnresolvedKnowledge(prior.knowledge.entries.single(), prior.knowledge.knowledgeId, "deferred", "old-run")), provenance = "fixture")
        assertFailsWith<ValidationException> { IdentityReferences.validate(listOf(external), apk, pending) }
        // The same canonical identity is a legitimate explicit retry reference.
        IdentityReferences.validate(listOf(prior), apk, pending)
        val oldApk = apk("older")
        val historical = reference(oldApk, "historical", listOf("La;" to "historical-id"))
        val historyOnly = pending.copy(unresolved = listOf(UnresolvedKnowledge(historical.knowledge.entries.single(),
            historical.knowledge.knowledgeId, "not migrated", "older-run")))
        IdentityReferences.validate(listOf(external), apk, historyOnly)
    }

    @Test fun `configuration name calls remain visible but do not become RPC role rows`() {
        val apk = apk()
        val profile = AnalysisProfile(id = "rpc", strategy = StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "factory")),
            rpcDrafts = RpcDraftOptions())
        val caller = MethodRef(ref(apk, "Lcaller;"), "run", "()V")
        val calls = listOf(RpcCallObservation(caller, 1, "fixture.Service", "ConfigurationOnly", "NON_CONSTRUCTION"),
            RpcCallObservation(caller, 2, "fixture.Service", "Read", "RESOLVED", listOf(ref(apk, "La;")), listOf(ref(apk, "Lb;"))))
        val discovery = AnalysisDiscovery(discoveryId = "fixture", engineBuildId = "test-build", apk = apk, profileSource = apk,
            profile = profile, classInventory = inventory, leads = emptyList(), matches = emptyList(), scan = ScanStats(3, 1, 3, 2, 0, emptyList()),
            matchCounts = emptyMap(), conditionCounts = emptyMap(), analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "fixture", rpcCalls = calls)
        val json = JsonFiles.gson.toJsonTree(RpcAnalysis.catalog(discovery)).asJsonObject
        assertEquals(2, json.getAsJsonArray("calls").size())
        assertEquals(2, json.getAsJsonArray("roles").size())
        assertTrue(json.getAsJsonArray("roles").all { it.asJsonObject.get("rpc").asString == "Read" })
        assertEquals(2, json.getAsJsonObject("counts").get("capturedServiceRpcPairs").asInt)
        assertEquals(1, json.getAsJsonObject("counts").get("serviceRpcPairs").asInt)
    }

    @Test fun `saved reference report and mapping cannot change after preparation`() {
        val apk = apk(); val reference = reference(apk, "reference")
        val (dir, _) = run(apk, task(apk, listOf(reference)), listOf(reference))
        AnalysisService.readRun(dir)
        Files.writeString(Path.of(reference.reportFile.path), "{}")
        assertFailsWith<ValidationException> { AnalysisService.readRun(dir) }
    }

    @Test fun `unresolved path source must exist in the actual run DEX inventory`() {
        val apk = apk()
        val original = proof(apk, listOf("La;"))
        val invalidSource = MethodRef(ClassRef(apk.sha256, "Lcaller;", "classes2.dex"), "call", "()V")
        val unresolved = RuleProofs.create(apk.sha256, original.rule, "test-build", original.matches,
            unresolvedPaths = listOf(UnresolvedPath(invalidSource, 4, "Unsupported constructor")))
        val item = AnalysisRuleItem("target", locators = unresolved.rule.locators)
        val task = AnalysisService.makeTask(apk, item, unresolved.rule, unresolved, null, null)
        val (dir, _) = run(apk, task, emptyList())
        assertFailsWith<ValidationException> { AnalysisService.readRun(dir) }
    }

    @Test fun `RPC profile options do not accept silent name templates or scope filters`() {
        val profile = AnalysisProfile(id = "rpc", strategy = StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "factory")),
            rpcDrafts = RpcDraftOptions(listOf("fixture.Group")))
        val path = temp.resolve("profile.json"); JsonFiles.writeNew(path, profile)
        assertEquals(profile, AnalysisService.readProfile(path))
        assertFailsWith<ValidationException> { RpcAnalysis.validate(profile.copy(nameCapture = "rpc")) }
        assertFailsWith<ValidationException> { RpcAnalysis.validate(profile.copy(rpcDrafts = RpcDraftOptions(listOf("fixture.Group", "fixture.Group")))) }
    }

    @Test fun `legacy schema four run fingerprint is unchanged when new fields are absent`() {
        // Golden digest produced by the installed pre-change 0.4.0 classes, not this implementation.
        val json = """{"schemaVersion":4,"kind":"analysis-run","runId":"","engineBuildId":"fixture-build","toolVersion":"0.4.0","jadxVersion":"1.5.0","apk":{"path":"fixture.apk","sha256":"fixture-sha"},"rulesFile":{"path":"rules.json","sha256":"rules-sha"},"rules":{"schemaVersion":4,"kind":"analysis-rules","minConfidence":"HIGH","items":[],"anchors":[]},"classInventory":{},"tasks":[],"scan":{"classCount":0,"methodCount":0,"instructionCount":0,"stringUseSites":0,"elapsedMillis":0,"diagnostics":[]},"analysisDiagnostics":[],"analysisMillis":0,"createdAt":"fixture","anchorTasks":[]}"""
        val run = JsonFiles.gson.fromJson(json, AnalysisRun::class.java)
        assertEquals("2a3d373cea6ec4f8b74a4f16786dd5da0b497131da2a63d495b00fe13cd33d6e", run.fingerprint())
        assertFalse(JsonFiles.encode(run).contains("identityReferences"))
        assertFalse(JsonFiles.encode(run).contains("rpcCalls"))
        assertFalse(JsonFiles.encode(AnalysisProfile(id = "legacy", discovery = Locator("string-use", "literal"))).contains("rpcDrafts"))
    }
}
