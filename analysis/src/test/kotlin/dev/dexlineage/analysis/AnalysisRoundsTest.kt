package dev.dexlineage.analysis

import com.google.gson.JsonObject
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

/** File/proof protocol fixtures; actual APK execution is covered by the CLI integration suite. */
class AnalysisRoundsTest {
    @TempDir lateinit var temp: Path
    private val inventory = mapOf("Llogger;" to "classes.dex", "Ltarget;" to "classes.dex", "Lother;" to "classes.dex")
    private fun artifact(): Artifact = Digests.artifact(temp.resolve("identity.apk").also { if (!Files.exists(it)) Files.writeString(it, "identity only") })
    private fun ref(apk: Artifact, name: String) = ClassRef(apk.sha256, name, "classes.dex")
    private fun json(vararg values: Pair<String, Any>): JsonObject = JsonFiles.gson.toJsonTree(values.toMap()).asJsonObject
    private fun factorySpec() = StrategySpec("builtin.method-signature", json("parameterTypes" to listOf("Ljava/lang/String;", "Ljava/lang/String;"), "returnSameAsOwner" to true), EntityKind.METHOD, mapOf("owner" to "logger"))
    private fun targetSpec() = StrategySpec("messages.logger-fields", json("component" to "Component"), requires = mapOf("factory" to "factory"))
    private fun definitions() = listOf(AnalysisAnchorDefinition("logger", listOf(Locator("string-use", "logger anchor"))), AnalysisAnchorDefinition("factory", strategy = factorySpec()))
    private fun fact(owner: ClassRef, method: MethodRef? = null, related: List<ClassRef> = emptyList()) = MatchFact(owner, MatchStatus.PASS,
        listOf(FactorResult("observed-relation", MatchStatus.PASS, "unit protocol fixture")), mapOf("component" to "Component"), method = method, relatedRefs = related)
    private fun rootProof(apk: Artifact): Resolution {
        val rule = RuleProofs.revision(definitions().first().locators)
        return RuleProofs.create(apk.sha256, rule, "test-build", listOf(fact(ref(apk, "Llogger;"))))
    }
    private fun saveRun(name: String, apk: Artifact, base: Pair<Path, VersionKnowledge>? = null, root: Resolution? = null,
                        factory: Resolution? = null, target: Resolution? = null): Pair<Path, AnalysisRun> {
        val directory = temp.resolve(name); Files.createDirectories(directory)
        val rules = AnalysisRuleFile(items = listOf(AnalysisRuleItem("component", proposedName = "Component", strategy = targetSpec())), anchors = definitions())
        val rulesPath = temp.resolve("$name-rules.json"); JsonFiles.writeNew(rulesPath, rules)
        val available = base?.second?.anchors.orEmpty().associateBy { it.key }
        val anchorTasks = rules.anchors.map { definition ->
            val rule = RuleProofs.revision(definition.locators, definition.strategy)
            val old = available[definition.key]
            val proof = old?.resolution ?: if (definition.key == "logger") root else factory
            AnalysisAnchorTask(definition.key, rule, proof, if (old != null) AnalysisExecutionState.INHERITED else if (proof == null) AnalysisExecutionState.WAITING_DEPENDENCY else AnalysisExecutionState.EXECUTED,
                if (proof == null) rule.requires.values.filter { it !in available }.sorted() else emptyList())
        }
        val targetRule = RuleProofs.revision(emptyList(), targetSpec())
        val targetTask = AnalysisService.makeTask(apk, rules.items.single(), targetRule, target, null, base?.second,
            waitingFor = if (target == null) listOf("factory") else emptyList())
        var run = AnalysisRun(runId = "", engineBuildId = "test-build", apk = apk, rulesFile = Digests.artifact(rulesPath), rules = rules,
            discoveryFile = null, discovery = null, baseFile = base?.first?.resolve("knowledge.json")?.let(Digests::artifact), baseKnowledge = base?.second,
            classInventory = inventory, tasks = listOf(targetTask), scan = ScanStats(3, 2, 3, 1, 0, emptyList()), analysisDiagnostics = emptyList(), analysisMillis = 0,
            createdAt = "fixture", anchorTasks = anchorTasks)
        run = run.copy(runId = run.fingerprint())
        JsonFiles.writeNew(directory.resolve("run.json"), run)
        val refs = listOfNotNull(root, factory, target).flatMap { proof -> proof.candidates.map { it.ref } + proof.matches.flatMap { it.relatedRefs } + KnowledgeFiles.evidenceClosure(proof).map { it.ref } }.distinct()
        if (refs.isNotEmpty()) EvidenceFiles.publish(directory, run.runId, apk, refs, refs.map { DecompiledClass(it.descriptor, "class ${Identities.rawName(it.descriptor)} {}", null, false, emptyList(), 0) })
        return directory to run
    }

    @Test fun `unique anchors publish without review and only the next snapshot enables a dependent round`() {
        val apk = artifact()
        val (firstDir, _) = saveRun("round1", apk, root = rootProof(apk))
        val queue = AnalysisService.tasks(firstDir, "WAITING_DEPENDENCY")
        assertEquals(1, queue.total)
        assertNull(queue.items.single().task.resolution)
        assertEquals(AnalysisExecutionState.WAITING_DEPENDENCY, queue.anchors.single { it.key == "factory" }.executionState)
        val firstOut = temp.resolve("published1")
        AnalysisService.publish(firstDir, firstOut)
        val first = KnowledgeFiles.read(firstOut.resolve("knowledge.json"))
        assertEquals(listOf("logger"), first.anchors.map { it.key })
        assertTrue(first.entries.isEmpty())
        assertEquals(listOf("tiny\t2\t0\tobfuscated\tnamed"), Files.readAllLines(firstOut.resolve("mapping.tiny")))

        val logger = first.anchors.single()
        val method = MethodRef(logger.binding.owner, "renamedFactory", "(Ljava/lang/String;Ljava/lang/String;)Llogger;")
        val factoryRule = RuleProofs.revision(emptyList(), factorySpec())
        val factoryProof = RuleProofs.create(apk.sha256, factoryRule, "test-build", listOf(fact(logger.binding.owner, method)), mapOf("owner" to logger))
        val (secondDir, _) = saveRun("round2", apk, firstOut to first, factory = factoryProof)
        assertNull(AnalysisService.tasks(secondDir, "WAITING_DEPENDENCY").items.single().task.resolution, "This round's new method cannot be consumed immediately")
        val secondOut = temp.resolve("published2"); AnalysisService.publish(secondDir, secondOut)
        val second = KnowledgeFiles.read(secondOut.resolve("knowledge.json"))
        assertEquals(2, second.anchors.size)
        assertTrue(second.entries.isEmpty())

        val resolvedFactory = second.anchors.single { it.key == "factory" }
        val rule = RuleProofs.revision(emptyList(), targetSpec())
        val targetProof = RuleProofs.create(apk.sha256, rule, "test-build", listOf(fact(ref(apk, "Ltarget;"), related = listOf(logger.binding.owner))), mapOf("factory" to resolvedFactory))
        val (thirdDir, thirdRun) = saveRun("round3", apk, secondOut to second, target = targetProof)
        val unreviewedOut = temp.resolve("unreviewed"); AnalysisService.publish(thirdDir, unreviewedOut)
        assertTrue(KnowledgeFiles.read(unreviewedOut.resolve("knowledge.json")).entries.isEmpty(), "Anchors do not grant rename approval")
        val review = AnalysisReview("component", targetProof.resolutionId, rule.revisionId, ReviewAction.ACCEPT, "Component", Confidence.HIGH,
            "Read the owner and resolved factory", evidenceIds = listOf(ref(apk, "Ltarget;"), logger.binding.owner).map { Identities.evidenceId(thirdRun.runId, it) })
        val reviewPath = temp.resolve("review.json"); JsonFiles.writeNew(reviewPath, AnalysisReviewBatch(runId = thirdRun.runId, apkSha256 = apk.sha256, items = listOf(review)))
        AnalysisService.submit(thirdDir, reviewPath)
        val finalOut = temp.resolve("final"); AnalysisService.publish(thirdDir, finalOut)
        val final = KnowledgeFiles.read(finalOut.resolve("knowledge.json"))
        assertEquals("Ltarget;", final.entries.single().binding.descriptor)
        assertEquals(2, final.anchors.size)
        assertEquals(2, Files.readAllLines(finalOut.resolve("mapping.tiny")).size)
    }

    @Test fun `changed root proof invalidates dependent anchor reuse without removing old knowledge`() {
        val apk = artifact()
        val root = rootProof(apk)
        val rootAnchor = SupportAnchor("logger", root.uniqueEntity!!, root.rule, root)
        val method = MethodRef(root.uniqueRef!!, "f", "(Ljava/lang/String;Ljava/lang/String;)Llogger;")
        val factoryRule = RuleProofs.revision(emptyList(), factorySpec())
        val factoryProof = RuleProofs.create(apk.sha256, factoryRule, "test-build", listOf(fact(root.uniqueRef!!, method)), mapOf("owner" to rootAnchor))
        val factoryAnchor = SupportAnchor("factory", factoryProof.uniqueEntity!!, factoryRule, factoryProof)
        val base = VersionKnowledge(knowledgeId = "fixture", artifact = apk, entries = emptyList(), unresolved = emptyList(), provenance = "fixture", anchors = listOf(rootAnchor, factoryAnchor))
        assertEquals(2, AnalysisService.usableAnchors(base, mapOf("logger" to root.rule, "factory" to factoryRule), "test-build").size)
        val revised = RuleProofs.revision(listOf(Locator("string-use", "replacement")))
        assertTrue(AnalysisService.usableAnchors(base, mapOf("logger" to revised, "factory" to factoryRule), "test-build").isEmpty())
        assertEquals(2, base.anchors.size)
    }

    @Test fun `corpus mismatch is checked after matching and unconfigured targets remain visible`() {
        val apk = artifact()
        val originals = listOf("Ltarget;" to "ManualTarget", "Lother;" to "OtherTarget").map { (descriptor, name) ->
            json("nodeRef" to mapOf("refType" to "CLASS", "declClass" to Identities.rawName(descriptor)), "newName" to name)
        }
        val projectPath = temp.resolve("manual.jadx")
        JsonFiles.writeNew(projectPath, mapOf("projectVersion" to 1, "codeData" to mapOf("renames" to originals)))
        val annotations = originals.map { original -> ManualAnnotation("CLASS", Identities.descriptor(original.getAsJsonObject("nodeRef").get("declClass").asString), null,
            original.get("newName").asString, null, original) }
        val targets = annotations.mapIndexed { index, a -> ManualTarget("manual-${Digests.text("${apk.sha256}\n${a.ownerDescriptor}")}", ref(apk, a.ownerDescriptor), a.name, index) }
        var corpus = ManualCorpus(corpusId = "", apk = apk, project = Digests.artifact(projectPath), projectVersion = 1, annotations = annotations, targets = targets,
            annotationCounts = mapOf("CLASS" to 2))
        corpus = corpus.copy(corpusId = corpus.fingerprint())
        val corpusPath = temp.resolve("corpus.json"); JsonFiles.writeNew(corpusPath, corpus)
        val page = AnalysisService.targets(corpusPath)
        assertEquals(mapOf("UNCONFIGURED" to 2), page.counts)
        val rule = RuleProofs.revision(listOf(Locator("string-use", "signal")))
        val proof = RuleProofs.create(apk.sha256, rule, "test-build", listOf(fact(ref(apk, "Lother;"))))
        val item = AnalysisRuleItem("target", locators = rule.locators, corpusTargetId = targets[0].targetId)
        val task = AnalysisService.makeTask(apk, item, rule, proof, null, null, corpus)
        assertEquals("manual_owner_mismatch", task.invalidReason)
        assertEquals("Lother;", task.resolution!!.uniqueRef!!.descriptor, "Expected manual owner must not change executed candidates")

        val correctProof = RuleProofs.create(apk.sha256, rule, "test-build", listOf(fact(ref(apk, "Ltarget;"))))
        val correct = AnalysisService.makeTask(apk, item, rule, correctProof, null, null, corpus)
        val rules = AnalysisRuleFile(items = listOf(item)); val rulesPath = temp.resolve("corpus-rules.json"); JsonFiles.writeNew(rulesPath, rules)
        val dir = temp.resolve("corpus-run"); Files.createDirectory(dir)
        var run = AnalysisRun(runId = "", engineBuildId = "test-build", apk = apk, rulesFile = Digests.artifact(rulesPath), rules = rules,
            discoveryFile = null, discovery = null, baseFile = null, baseKnowledge = null, classInventory = inventory, tasks = listOf(correct),
            scan = ScanStats(3, 1, 1, 0, 0, emptyList()), analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "fixture",
            corpusFile = Digests.artifact(corpusPath), corpus = corpus)
        run = run.copy(runId = run.fingerprint()); JsonFiles.writeNew(dir.resolve("run.json"), run)
        EvidenceFiles.publish(dir, run.runId, apk, listOf(ref(apk, "Ltarget;")), listOf(DecompiledClass("Ltarget;", "class target {}", null, false, emptyList(), 0)))
        val packet = ReviewPackets.write(dir, setOf("target"), temp.resolve("packet"))
        ReviewPackets.validate(temp.resolve("packet"), dir, setOf("target"))
        val template = JsonFiles.read(Path.of(packet.templatePath), AnalysisReviewBatch::class.java)
        assertEquals("ManualTarget", template.items.single().name)
        assertFailsWith<ValidationException> { AnalysisService.submit(dir, Path.of(packet.templatePath)) }
    }
}
