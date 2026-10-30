package dev.dexlineage.cli.fixtures

import com.google.gson.JsonObject
import dev.dexlineage.analysis.*
import dev.dexlineage.migration.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.test.*

/** Real subprocess regression. Semantic truth is declared here before any candidate is read. */
@Tag("fixture-integration")
class MultiRoundIntegrationTest {
    private val namespace = "dev.dexlineage.fixture.rounds."
    private val names = linkedMapOf("LoggerBusiness" to "ReviewedRoundCache", "NamedHandler" to "RoundHandler",
        "RequestRecord" to "ReadRecordRequest", "ResponseRecord" to "ReadRecordResponse")
    private lateinit var cli: FixtureCli
    private lateinit var workspace: Path
    private lateinit var manifest: FixtureManifest
    private lateinit var oracle: Map<String, R8Oracle>
    private fun apk(version: String) = workspace.resolve(manifest.versions.getValue(version).apk)
    private fun descriptor(version: String, source: String) = oracle.getValue(version).descriptor(namespace + source)
    private fun sourceType(source: String) = "L${(namespace + source).replace('.', '/')};"
    private fun parameters(vararg entries: Pair<String, Any>): JsonObject = JsonObject().apply {
        entries.forEach { (key, value) -> add(key, cli.gson.toJsonTree(value)) }
    }
    private fun strategy(id: String, params: JsonObject = JsonObject(), kind: EntityKind = EntityKind.CLASS,
        vararg dependencies: Pair<String, String>) = StrategySpec(id, params, kind, dependencies.toMap())

    @Test fun `compiled strategies use current anchors across immutable CLI rounds`() {
        workspace = Path.of(System.getProperty("dexlineage.fixtureRoot")).toAbsolutePath().parent.parent
        manifest = FixtureManifest.read(Path.of(System.getProperty("dexlineage.fixtureCases")))
        cli = FixtureCli(Path.of(System.getProperty("dexlineage.distributionDir")),
            Path.of(System.getProperty("dexlineage.fixtureResults")).resolve("rounds-${UUID.randomUUID()}"), workspace)
        oracle = manifest.versions.mapValues { (_, value) -> R8Oracle(workspace.resolve(value.mapping)) }
        names.keys.forEach { assertNotEquals(descriptor("v1", it), descriptor("v2", it)) }

        // The source oracle produces a simulated manual project, not matcher parameters.
        // All matching still runs over the full APK; this corpus is a post-match source assertion.
        val renames = (names + ("UnconfiguredTarget" to "UnconfiguredTarget")).map { (type, alias) ->
            mapOf("nodeRef" to mapOf("refType" to "CLASS", "declClass" to descriptor("v1", type).drop(1).dropLast(1).replace('/', '.')), "newName" to alias)
        }
        val project = cli.write("manual/project.jadx", mapOf("projectVersion" to 1, "files" to listOf(apk("v1").toString()), "codeData" to mapOf("renames" to renames)))
        val corpusDir = cli.output.resolve("corpus")
        cli.execute("import-manual", "analysis", "import-jadx", "--apk", apk("v1"), "--project", project, "--out", corpusDir)
        val corpusPath = corpusDir.resolve("corpus.json")
        val corpus = cli.read<ManualCorpus>(corpusPath)
        assertEquals(5, corpus.targets.size)
        val emptyLedger = cli.result<CorpusTargetPage>("initial-targets", "analysis", "targets", "--corpus", corpusPath, "--limit", 100)
        assertEquals(5, emptyLedger.total)
        assertTrue(emptyLedger.items.all { it.state == "UNCONFIGURED" })
        val wrongManual = corpus.targets.single { it.manualName == "UnconfiguredTarget" }
        val mismatchRules = cli.write("inputs/corpus-mismatch.json", AnalysisRuleFile(items = listOf(
            AnalysisRuleItem("mismatch", proposedName = wrongManual.manualName, corpusTargetId = wrongManual.targetId,
                locators = listOf(Locator("string-use", "RoundLoggerAnchor"))))))
        val mismatchDir = cli.output.resolve("corpus-mismatch")
        cli.execute("corpus-mismatch-prepare", "analysis", "prepare", "--apk", apk("v1"), "--corpus", corpusPath,
            "--rules", mismatchRules, "--run", mismatchDir)
        val mismatch = cli.read<AnalysisRun>(mismatchDir.resolve("run.json"))
        assertClass(mismatch.tasks.single().resolution!!, "v1", "RoundLogger")
        assertNotNull(mismatch.tasks.single().invalidReason, "A manual owner must not restrict search to manufacture a match")
        val mismatchReview = cli.write("reviews/corpus-mismatch.json", AnalysisReviewBatch(runId = mismatch.runId, apkSha256 = mismatch.apk.sha256,
            items = listOf(AnalysisReview("mismatch", mismatch.tasks.single().resolution!!.resolutionId, mismatch.tasks.single().rule.revisionId,
                ReviewAction.ACCEPT, wrongManual.manualName, Confidence.HIGH, "Deliberate incorrect source identity."))))
        cli.execute("corpus-mismatch-rejected", "analysis", "submit", "--run", mismatchDir, "--review", mismatchReview, expectedExit = 2)
        val anchors = listOf(
            AnalysisAnchorDefinition("logger", listOf(Locator("string-use", "RoundLoggerAnchor"))),
            AnalysisAnchorDefinition("lifecycle", listOf(Locator("string-use", "Executing fixture handler: class=%s request=%s"))),
            AnalysisAnchorDefinition("ambiguous", listOf(Locator("string-use", "AmbiguousLoggerAnchor"))),
            AnalysisAnchorDefinition("unknown-lifecycle", listOf(Locator("string-use", "Uncertain fixture handler: class=%s request=%s"))),
            AnalysisAnchorDefinition("factory", strategy = strategy("builtin.method-signature",
                parameters("parameterTypes" to listOf("Ljava/lang/String;", "Ljava/lang/String;"), "returnSameAsOwner" to true, "requiredFlags" to listOf("STATIC")), EntityKind.METHOD, "owner" to "logger")),
            AnalysisAnchorDefinition("ambiguous-factory", strategy = strategy("builtin.method-signature",
                parameters("parameterTypes" to listOf("Ljava/lang/String;", "Ljava/lang/String;"), "returnSameAsOwner" to true, "requiredFlags" to listOf("STATIC")), EntityKind.METHOD, "owner" to "ambiguous")),
            AnalysisAnchorDefinition("name-method", strategy = strategy("messages.handler-name-method",
                parameters("logLiteral" to "Executing fixture handler: class=%s request=%s", "argumentIndex" to 0), EntityKind.METHOD, "lifecycle" to "lifecycle")),
            AnalysisAnchorDefinition("unknown-name-method", strategy = strategy("messages.handler-name-method",
                parameters("logLiteral" to "Uncertain fixture handler: class=%s request=%s", "argumentIndex" to 0), EntityKind.METHOD, "lifecycle" to "unknown-lifecycle")),
            AnalysisAnchorDefinition("rpc", strategy = strategy("messages.rpc-descriptor", parameters("service" to "fixture.Sample", "rpc" to "ReadRecord"), EntityKind.METHOD)),
            AnalysisAnchorDefinition("split-rpc", strategy = strategy("messages.rpc-descriptor", parameters("service" to "fixture.Split", "rpc" to "ReadRecord"), EntityKind.METHOD)),
            AnalysisAnchorDefinition("swapped-rpc", strategy = strategy("messages.rpc-descriptor", parameters("service" to "fixture.Swapped", "rpc" to "ReadRecord"), EntityKind.METHOD)))
        fun item(source: String, spec: StrategySpec) = AnalysisRuleItem(source, proposedName = names.getValue(source), strategy = spec,
            corpusTargetId = corpus.targets.single { it.source.descriptor == descriptor("v1", source) }.targetId)
        val items = listOf(
            item("LoggerBusiness", strategy("messages.logger-fields", parameters("component" to "RoundCache"), EntityKind.CLASS, "factory" to "factory")),
            item("NamedHandler", strategy("messages.named-handler", parameters("component" to "RoundHandler"), EntityKind.CLASS, "nameMethod" to "name-method")),
            item("RequestRecord", strategy("messages.rpc-message", parameters("service" to "fixture.Sample", "rpc" to "ReadRecord", "role" to "request"), EntityKind.CLASS, "descriptor" to "rpc")),
            item("ResponseRecord", strategy("messages.rpc-message", parameters("service" to "fixture.Sample", "rpc" to "ReadRecord", "role" to "response"), EntityKind.CLASS, "descriptor" to "rpc")),
            AnalysisRuleItem("duplicate", proposedName = "DuplicateHandler", strategy = strategy("messages.named-handler", parameters("component" to "DuplicateHandler"), EntityKind.CLASS, "nameMethod" to "name-method")),
            AnalysisRuleItem("unknown", proposedName = "UnknownPeer", strategy = strategy("messages.named-handler", parameters("component" to "UnknownPeer"), EntityKind.CLASS, "nameMethod" to "unknown-name-method")),
            AnalysisRuleItem("blocked", proposedName = "NeverPublished", strategy = strategy("messages.logger-fields", parameters("component" to "RoundCache"), EntityKind.CLASS, "factory" to "ambiguous-factory")),
            AnalysisRuleItem("split", proposedName = "NeverSpliced", strategy = strategy("messages.rpc-message", parameters("service" to "fixture.Split", "rpc" to "ReadRecord", "role" to "request"), EntityKind.CLASS, "descriptor" to "split-rpc")),
            AnalysisRuleItem("swapped", proposedName = "NeverAssumeRequest", strategy = strategy("messages.rpc-message", parameters("service" to "fixture.Swapped", "rpc" to "ReadRecord", "role" to "request"), EntityKind.CLASS, "descriptor" to "swapped-rpc")))
        val rules = cli.write("inputs/rules.json", AnalysisRuleFile(items = items, anchors = anchors))
        var base: Path? = null
        var lastRun: AnalysisRun? = null
        var lastDir: Path? = null
        for (round in 1..3) {
            val dir = cli.output.resolve("source-round-$round")
            val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk("v1"), "--rules", rules, "--corpus", corpusPath, "--run", dir)
            base?.let { args.addAll(listOf("--base-knowledge", it.resolve("knowledge.json"))) }
            cli.execute("source-$round-prepare", *args.toTypedArray())
            val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
            if (round == 1) {
                assertTrue(run.tasks.all { it.resolution == null && it.waitingFor.isNotEmpty() })
                assertNull(run.anchorTasks.single { it.key == "factory" }.resolution, "No same-command propagation")
                assertMethod(run.anchorTasks.single { it.key == "rpc" }.resolution!!, "v1", "RpcDescriptors", "read", "()${sourceType("Descriptor")}")
            }
            if (round >= 2) {
                assertMethod(run.anchorTasks.single { it.key == "factory" }.resolution ?: run.baseKnowledge!!.anchors.single { it.key == "factory" }.resolution, "v1", "RoundLogger", "create", "(Ljava/lang/String;Ljava/lang/String;)${sourceType("RoundLogger")}")
                val ambiguous = run.anchorTasks.single { it.key == "ambiguous-factory" }.resolution!!
                assertEquals(ResolutionStatus.AMBIGUOUS, ambiguous.status)
                assertEquals(2, ambiguous.candidates.size)
                assertEquals(1, ambiguous.candidates.map { it.ref }.distinct().size)
                assertMethod(run.anchorTasks.single { it.key == "name-method" }.resolution ?: run.baseKnowledge!!.anchors.single { it.key == "name-method" }.resolution, "v1", "HandlerContract", "componentName", "()Ljava/lang/String;")
            }
            val reviews = mutableListOf<AnalysisReview>()
            for (task in run.tasks.filter { it.taskId in names && it.executionState == AnalysisExecutionState.EXECUTED }) {
                assertClass(task.resolution!!, "v1", task.taskId)
                val evidence = inspect("analysis", dir, task.taskId)
                reviews += AnalysisReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT,
                    names.getValue(task.taskId), Confidence.HIGH, "Fixture-authored ${task.taskId} role confirmed against independent source/R8 oracle.",
                    listOf("Static protocol regression; no runtime behavior claim."), evidence.map { it.evidenceId })
            }
            if (reviews.isNotEmpty()) {
                val file = cli.write("reviews/source-$round.json", AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256, items = reviews))
                cli.execute("source-$round-submit", "analysis", "submit", "--run", dir, "--review", file)
                cli.execute("source-$round-retry", "analysis", "submit", "--run", dir, "--review", file)
            }
            val out = cli.output.resolve("source-published-$round")
            cli.execute("source-$round-publish", "analysis", "publish", "--run", dir, "--out", out)
            verifyRoundPublished(out, "v1", round)
            if (round == 1) assertTrue(cli.read<VersionKnowledge>(out.resolve("knowledge.json")).entries.isEmpty())
            base = out; lastRun = run; lastDir = dir
        }
        val sourceOut = base!!
        val source = cli.read<VersionKnowledge>(sourceOut.resolve("knowledge.json"))
        assertEquals(names.keys.map { descriptor("v1", it) }.toSet(), source.entries.map { it.binding.descriptor }.toSet())
        val ledger = cli.result<CorpusTargetPage>("final-targets", "analysis", "targets", "--corpus", corpusPath, "--run", lastDir!!, "--limit", 100)
        assertEquals(5, ledger.total)
        assertEquals("UNCONFIGURED", ledger.items.single { it.target.manualName == "UnconfiguredTarget" }.state)
        assertEquals(ResolutionStatus.AMBIGUOUS, lastRun!!.tasks.single { it.taskId == "duplicate" }.resolution!!.status)
        assertEquals(ResolutionStatus.UNKNOWN, lastRun.tasks.single { it.taskId == "unknown" }.resolution!!.status)
        assertNull(lastRun.tasks.single { it.taskId == "blocked" }.resolution)
        assertNotEquals(ResolutionStatus.UNIQUE, lastRun.tasks.single { it.taskId == "split" }.resolution?.status)
        assertClass(lastRun.tasks.single { it.taskId == "swapped" }.resolution!!, "v1", "ResponseRecord")
        verify(sourceOut, "v1", source)
        val replay = cli.output.resolve("source-replay")
        cli.execute("source-replay", "analysis", "publish", "--run", lastDir, "--out", replay, "--at", sourceOut.resolve("report.json"))
        assertEquals(Files.readString(sourceOut.resolve("knowledge.json")), Files.readString(replay.resolve("knowledge.json")))
        verifyRoundPublished(replay, "v1", 3)
        PublishedFixtureAssertions.negativeCopies(cli, apk("v1"), sourceOut.resolve("knowledge.json"), oracle.getValue("v1"),
            entryTruth(), anchorTruth("v1"), namespace + "UnconfiguredTarget")

        val changedRules = cli.write("inputs/dependency-changed.json", AnalysisRuleFile(items = items, anchors = anchors.map {
            if (it.key == "logger") it.copy(locators = listOf(Locator("string-use", "AbsentRoundLoggerAnchor"))) else it
        }))
        val changedDir = cli.output.resolve("dependency-changed")
        cli.execute("dependency-changed-prepare", "analysis", "prepare", "--apk", apk("v1"), "--corpus", corpusPath,
            "--rules", changedRules, "--base-knowledge", sourceOut.resolve("knowledge.json"), "--run", changedDir)
        val changed = cli.read<AnalysisRun>(changedDir.resolve("run.json"))
        val waitingCache = changed.tasks.single { it.taskId == "LoggerBusiness" }
        assertEquals(AnalysisExecutionState.WAITING_DEPENDENCY, waitingCache.executionState)
        assertNull(waitingCache.resolution)
        val oldReview = cli.read<AnalysisReviewBatch>(cli.output.resolve("reviews/source-3.json")).items.single { it.taskId == "LoggerBusiness" }
        val stale = cli.write("reviews/stale-dependency.json", AnalysisReviewBatch(runId = changed.runId, apkSha256 = changed.apk.sha256, items = listOf(oldReview)))
        cli.execute("stale-dependency-review-rejected", "analysis", "submit", "--run", changedDir, "--review", stale, expectedExit = 2)
        val retained = cli.output.resolve("dependency-change-retained")
        cli.execute("dependency-change-retained", "analysis", "publish", "--run", changedDir, "--out", retained)
        assertEquals(source.entries, cli.read<VersionKnowledge>(retained.resolve("knowledge.json")).entries)
        assertEquals(Files.readString(sourceOut.resolve("mapping.tiny")), Files.readString(retained.resolve("mapping.tiny")))
        verifyRoundPublished(retained, "v1", 3)
        cli.execute("wrong-apk-dependencies", "analysis", "prepare", "--apk", apk("v2"), "--rules", rules,
            "--base-knowledge", sourceOut.resolve("knowledge.json"), "--run", cli.output.resolve("wrong-apk"), expectedExit = 2)
        cli.execute("source-is-not-target-base", "migration", "prepare", "--knowledge", sourceOut.resolve("knowledge.json"),
            "--source-apk", apk("v1"), "--target-apk", apk("v2"), "--target-base", sourceOut.resolve("knowledge.json"),
            "--run", cli.output.resolve("wrong-target-base"), expectedExit = 2)
        val broken = cli.output.resolve("broken-ancestor-package")
        Files.walk(sourceOut).use { paths -> paths.forEach { path ->
            val copy = broken.resolve(sourceOut.relativize(path))
            if (Files.isDirectory(path)) Files.createDirectories(copy) else Files.copy(path, copy)
        } }
        val ancestor = source.anchors.single { it.key == "factory" }.resolution.dependencies.getValue("owner").evidence.first()
        Files.delete(broken.resolve(ancestor.javaPath))
        cli.execute("missing-ancestor-evidence", "knowledge", "verify", "--knowledge", broken.resolve("knowledge.json"),
            "--apk", apk("v1"), "--work", cli.output.resolve("missing-ancestor-readback"), expectedExit = 2)
        Files.writeString(broken.resolve(ancestor.javaPath), "changed ancestor evidence")
        cli.execute("changed-ancestor-evidence", "analysis", "prepare", "--apk", apk("v1"), "--rules", rules,
            "--base-knowledge", broken.resolve("knowledge.json"), "--run", cli.output.resolve("bad-ancestor-run"), expectedExit = 2)

        base = null
        for (round in 1..3) {
            val dir = cli.output.resolve("target-round-$round")
            val args = mutableListOf<Any>("migration", "prepare", "--knowledge", sourceOut.resolve("knowledge.json"),
                "--source-apk", apk("v1"), "--target-apk", apk("v2"), "--run", dir)
            base?.let { args.addAll(listOf("--target-base", it.resolve("knowledge.json"))) }
            cli.execute("target-$round-prepare", *args.toTypedArray())
            val run = cli.read<MigrationRun>(dir.resolve("run.json"))
            assertEquals(source.entries.map { it.semanticId }.toSet(), run.tasks.map { it.taskId }.toSet())
            run.tasks.forEach { task ->
                assertEquals(task.entry.ruleRevision, task.rule, "Migration must preserve the exact source rule")
                task.resolution?.let { proof ->
                    assertEquals(RawDex.read(apk("v2")).apkSha256, proof.apkSha256)
                    assertNotEquals(task.entry.resolution!!.resolutionId, proof.resolutionId)
                    assertNotEquals(task.entry.binding.apkSha256, proof.apkSha256)
                }
            }
            run.anchorTasks.forEach { task ->
                val old = source.anchors.single { it.key == task.key }
                assertEquals(old.rule, task.rule, "Anchor strategy/parameters/dependencies must remain unchanged")
                task.resolution?.let { proof ->
                    assertEquals(RawDex.read(apk("v2")).apkSha256, proof.apkSha256)
                    assertNotEquals(old.resolution.resolutionId, proof.resolutionId)
                }
            }
            cli.write("proof-handoff/target-round-$round.json", mapOf("schemaVersion" to 1, "runId" to run.runId,
                "sourceKnowledgeId" to source.knowledgeId, "targetApkSha256" to run.targetApk.sha256,
                "tasks" to run.tasks.map { task -> mapOf("semanticId" to task.taskId,
                    "ruleRevisionId" to task.rule.revisionId, "sourceResolutionId" to task.entry.resolution!!.resolutionId,
                    "targetResolutionId" to task.resolution?.resolutionId, "unchangedRuleAsserted" to true,
                    "executionState" to task.executionState) },
                "anchors" to run.anchorTasks.map { task -> mapOf("key" to task.key,
                    "ruleRevisionId" to task.rule.revisionId, "targetResolutionId" to task.resolution?.resolutionId,
                    "unchangedRuleAsserted" to true) }, "status" to "PASS"))
            if (round == 1) {
                assertTrue(run.tasks.all { it.resolution == null }, "Source anchors must not satisfy target dependencies")
                assertMethod(run.anchorTasks.single { it.key == "rpc" }.resolution!!, "v2", "RpcStub", "read", "()${sourceType("Descriptor")}")
            }
            if (round >= 2) assertMethod(run.anchorTasks.single { it.key == "factory" }.resolution ?: run.targetBase!!.anchors.single { it.key == "factory" }.resolution, "v2", "RoundLogger", "construct", "(Ljava/lang/String;Ljava/lang/String;)${sourceType("RoundLogger")}")
            val reviews = run.tasks.filter { it.executionState == MigrationExecutionState.EXECUTED }.map { task ->
                val type = names.entries.single { it.value == task.entry.name }.key
                assertClass(task.resolution!!, "v2", type)
                val evidence = inspect("migration", dir, task.taskId)
                MigrationReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT, Confidence.HIGH, true,
                    "Independent fixture source preserves the $type role across versions.",
                    listOf("R8 symbols, factory method, constructor parameter order and descriptor owner change."),
                    listOf("Fixture truth only; no Agent quality or runtime behavior claim."), evidence.map { it.evidenceId })
            }
            if (reviews.isNotEmpty()) {
                val file = cli.write("reviews/target-$round.json", MigrationReviewBatch(runId = run.runId, sourceKnowledgeId = source.knowledgeId,
                    sourceApkSha256 = run.sourceApk.sha256, targetApkSha256 = run.targetApk.sha256, items = reviews))
                cli.execute("target-$round-submit", "migration", "submit", "--run", dir, "--review", file)
            }
            val out = cli.output.resolve("target-published-$round")
            cli.execute("target-$round-publish", "migration", "publish", "--run", dir, "--out", out)
            verifyRoundPublished(out, "v2", round)
            base = out
        }
        val target = cli.read<VersionKnowledge>(base!!.resolve("knowledge.json"))
        assertEquals(names.values.toSet(), target.entries.map { it.name }.toSet())
        assertEquals(source.entries.map { it.semanticId }.toSet(), target.entries.map { it.semanticId }.toSet())
        assertTrue(target.unresolved.isEmpty())
        assertTrue(target.anchors.all { it.binding.owner.apkSha256 == target.artifact.sha256 })
        target.entries.forEach { entry ->
            val old = source.entries.single { it.semanticId == entry.semanticId }
            assertEquals(old.ruleRevision, entry.ruleRevision)
            assertNotEquals(old.resolution!!.resolutionId, entry.resolution!!.resolutionId)
        }
        verify(base, "v2", target)
        val targetReplay = cli.output.resolve("target-replay")
        cli.execute("target-replay", "migration", "publish", "--run", cli.output.resolve("target-round-3"), "--out", targetReplay,
            "--at", base.resolve("report.json"))
        for (file in listOf("knowledge.json", "mapping.tiny")) assertEquals(Files.readString(base.resolve(file)), Files.readString(targetReplay.resolve(file)))
        verifyRoundPublished(targetReplay, "v2", 3)
        verifyUnsupportedCompetitors()
        cli.write("summary.json", mapOf("schemaVersion" to 4, "sourceClasses" to source.entries.size, "targetClasses" to target.entries.size,
            "anchors" to target.anchors.size, "roundsPerVersion" to 3, "commands" to cli.commandCount,
            "commandTimings" to cli.timingSummary, "publishedDexReports" to "dex-consumption"))
    }

    private fun verifyUnsupportedCompetitors() {
        val anchors = listOf(
            AnalysisAnchorDefinition("escaped-lifecycle", listOf(Locator("string-use", "Escaped fixture handler: class=%s request=%s"))),
            AnalysisAnchorDefinition("escaped-name", strategy = strategy("messages.handler-name-method",
                parameters("logLiteral" to "Escaped fixture handler: class=%s request=%s", "argumentIndex" to 0), EntityKind.METHOD, "lifecycle" to "escaped-lifecycle"))) +
            listOf("Setter", "Helper", "Mixed").map { kind -> AnalysisAnchorDefinition(kind.lowercase(), strategy = strategy("messages.rpc-descriptor",
                parameters("service" to "fixture.$kind", "rpc" to "ReadRecord"), EntityKind.METHOD)) }
        val rules = cli.write("inputs/unsupported-relations.json", AnalysisRuleFile(anchors = anchors))
        for (version in listOf("v1", "v2")) {
            var base: Path? = null
            for (round in 1..2) {
                val dir = cli.output.resolve("unsupported-$version-$round")
                val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk(version), "--rules", rules, "--run", dir)
                base?.let { args.addAll(listOf("--base-knowledge", it.resolve("knowledge.json"))) }
                cli.execute("unsupported-$version-$round", *args.toTypedArray())
                val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
                for (key in listOf("setter", "helper", "mixed")) assertEquals(ResolutionStatus.UNKNOWN,
                    run.anchorTasks.single { it.key == key }.resolution!!.status, "$version unsupported $key must not disappear")
                val mixed = run.anchorTasks.single { it.key == "mixed" }.resolution!!
                assertEquals(setOf(MatchStatus.PASS, MatchStatus.UNKNOWN), mixed.candidates.map { it.status }.toSet())
                assertEquals(2, mixed.candidates.size)
                if (round == 2) assertEquals(ResolutionStatus.UNKNOWN, run.anchorTasks.single { it.key == "escaped-name" }.resolution!!.status)
                val out = cli.output.resolve("unsupported-published-$version-$round")
                cli.execute("unsupported-publish-$version-$round", "analysis", "publish", "--run", dir, "--out", out)
                val knowledge = cli.read<VersionKnowledge>(out.resolve("knowledge.json"))
                assertTrue(knowledge.entries.isEmpty())
                assertEquals(setOf("escaped-lifecycle"), knowledge.anchors.map { it.key }.toSet())
                PublishedFixtureAssertions.verify(cli, apk(version), out.resolve("knowledge.json"), oracle.getValue(version),
                    emptyMap(), mapOf("escaped-lifecycle" to ExpectedPublishedAnchor(namespace + "EscapedLifecycle")))
                base = out
            }
        }
    }

    private fun inspect(scene: String, dir: Path, id: String): List<EvidenceRecord> =
        cli.result<Array<EvidenceRecord>>("${dir.fileName}-$id-inspect", scene, "inspect", "--run", dir, "--task", id).toList()
    private fun assertClass(result: Resolution, version: String, original: String) {
        assertEquals(ResolutionStatus.UNIQUE, result.status, "$version $original: ${result.matches}")
        assertEquals(descriptor(version, original), result.uniqueRef!!.descriptor)
    }
    private fun assertMethod(result: Resolution, version: String, original: String, name: String, sourceDescriptor: String) {
        assertEquals(ResolutionStatus.UNIQUE, result.status, "$original.$name")
        val method = result.uniqueMethod!!
        val expected = oracle.getValue(version).method(namespace + original, name, sourceDescriptor)
        assertEquals(expected.owner, method.owner.descriptor)
        assertEquals(expected.name, method.name)
        assertEquals(expected.descriptor, method.descriptor, "Full method parameters AND return type must match")
    }
    private fun entryTruth() = names.entries.associate { it.value to namespace + it.key }
    private fun anchorTruth(version: String): Map<String, ExpectedPublishedAnchor> {
        val rpcOwner = namespace + if (version == "v1") "RpcDescriptors" else "RpcStub"
        return mapOf(
            "logger" to ExpectedPublishedAnchor(namespace + "RoundLogger"),
            "lifecycle" to ExpectedPublishedAnchor(namespace + "Lifecycle"),
            "ambiguous" to ExpectedPublishedAnchor(namespace + "AmbiguousLogger"),
            "unknown-lifecycle" to ExpectedPublishedAnchor(namespace + "UnknownLifecycle"),
            "factory" to ExpectedPublishedAnchor(namespace + "RoundLogger", if (version == "v1") "create" else "construct",
                "(Ljava/lang/String;Ljava/lang/String;)${sourceType("RoundLogger")}"),
            "name-method" to ExpectedPublishedAnchor(namespace + "HandlerContract", "componentName", "()Ljava/lang/String;"),
            "unknown-name-method" to ExpectedPublishedAnchor(namespace + "UnknownContract", "componentName", "()Ljava/lang/String;"),
            "rpc" to ExpectedPublishedAnchor(rpcOwner, "read", "()${sourceType("Descriptor")}"),
            "swapped-rpc" to ExpectedPublishedAnchor(rpcOwner, "swapped", "()${sourceType("Descriptor")}"))
    }
    private fun memberTruth() = mapOf(
        names.getValue("LoggerBusiness") to ExpectedPublishedMembers(
            fields = listOf(ExpectedPublishedField("LOGGER", sourceType("RoundLogger"), 0x1a)),
            methods = listOf(ExpectedPublishedMethod("describe", "()Ljava/lang/String;"))),
        names.getValue("NamedHandler") to ExpectedPublishedMembers(methods = listOf(
            ExpectedPublishedMethod("componentName", "()Ljava/lang/String;", 0x1),
            ExpectedPublishedMethod("requestId", "()Ljava/lang/String;", 0x1))),
        names.getValue("RequestRecord") to ExpectedPublishedMembers(fields = listOf(
            ExpectedPublishedField("DEFAULT", sourceType("RequestRecord"), 0x18))),
        names.getValue("ResponseRecord") to ExpectedPublishedMembers(fields = listOf(
            ExpectedPublishedField("DEFAULT", sourceType("ResponseRecord"), 0x18))))

    private fun verifyRoundPublished(out: Path, version: String, round: Int): PublishedDexFacts {
        val facts = PublishedFixtureAssertions.verify(cli, apk(version), out.resolve("knowledge.json"), oracle.getValue(version),
            entryTruth(), anchorTruth(version), memberTruth())
        val expectedNames = when (round) {
            1 -> emptySet()
            2 -> setOf(names.getValue("RequestRecord"), names.getValue("ResponseRecord"))
            else -> names.values.toSet()
        }
        assertEquals(expectedNames, facts.entries.map { it.name }.toSet(), "Round $round confirmed entry set")
        val firstKeys = setOf("logger", "lifecycle", "ambiguous", "unknown-lifecycle", "rpc", "swapped-rpc")
        assertEquals(if (round == 1) firstKeys else anchorTruth(version).keys, facts.anchors.map { it.key }.toSet(), "Round $round support anchor set")
        return facts
    }
    private fun verify(out: Path, version: String, knowledge: VersionKnowledge) {
        val lines = Files.readAllLines(out.resolve("mapping.tiny"))
        assertEquals(knowledge.entries.size + 1, lines.size)
        assertTrue(lines.drop(1).all { it.startsWith("c\t") })
        val found = cli.result<Array<VerifiedRename>>("${out.fileName}-verify", "knowledge", "verify", "--knowledge", out.resolve("knowledge.json"),
            "--apk", apk(version), "--work", out.resolve("readback"))
        assertEquals(knowledge.entries.map { it.binding.descriptor }.toSet(), found.map { it.descriptor }.toSet())
    }
}
