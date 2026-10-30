package dev.dexlineage.analysis.workspace

import dev.dexlineage.analysis.*
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.ReviewStore
import com.google.gson.JsonObject
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.*

/** File-protocol/crash fixtures only: no synthetic APK, matcher or fake semantic acceptance. */
class WorkspaceTest {
    @TempDir lateinit var temp: Path

    private fun fixture(seedCount: Int = 1): Pair<WorkspaceEngine, FakeActions> {
        val apk = temp.resolve("input.bin"); if (!Files.exists(apk)) Files.writeString(apk, "file identity only; never parsed as APK")
        val profile = temp.resolve("profile.json"); if (!Files.exists(profile)) Files.writeString(profile, "{\"schemaVersion\":4}")
        val config = temp.resolve("config.json"); if (!Files.exists(config)) Files.writeString(config, "{\"schemaVersion\":4,\"fixture\":true}")
        val actions = FakeActions(seedCount)
        return WorkspaceEngine(actions) to actions
    }

    private fun run(engine: WorkspaceEngine) = engine.run("profile", temp.resolve("config.json"), temp.resolve("workspace"))
    private fun state(): WorkspaceRecord = JsonFiles.read(temp.resolve("workspace/workspace.json"), WorkspaceRecord::class.java)
    private fun writeState(value: WorkspaceRecord) = writeWorkspaceJson(temp.resolve("workspace/workspace.json"), value)
    private fun approve(status: WorkspaceStatus, action: String = "ACCEPT") {
        ReviewStore.submit(Path.of(status.runPath!!), "fixture-run", "selected", null, mapOf("action" to action))
    }

    @Test fun `journal completion drives resume while out of scope unreviewed does not block`() {
        val (engine, actions) = fixture()
        val waiting = run(engine)
        assertEquals(WorkspaceState.WAITING_REVIEW, waiting.state)
        assertEquals(listOf("selected"), waiting.pendingTaskIds)
        assertEquals(listOf("invalid", "inherited", "selected"), waiting.selectedTaskIds)
        val before = Files.readAllBytes(temp.resolve("workspace/workspace.json"))
        val count = actions.calls.toMap()
        assertEquals(waiting, engine.status(temp.resolve("workspace")))
        assertContentEquals(before, Files.readAllBytes(temp.resolve("workspace/workspace.json")), "status must not rewrite progress")
        assertEquals(count, actions.calls)
        approve(waiting, "DEFER")
        val complete = engine.resume(temp.resolve("workspace"))
        assertEquals(WorkspaceState.COMPLETE, complete.state)
        assertTrue(Files.isRegularFile(Path.of(complete.knowledgePath!!)))
        val completedCalls = actions.calls.toMap()
        assertEquals(complete, engine.resume(temp.resolve("workspace")))
        assertEquals(completedCalls, actions.calls, "Completed resume must execute no stage")
    }

    @Test fun `complete output without receipt is adopted after a crash`() {
        val (engine, actions) = fixture()
        actions.failAfter = "seed-1"
        assertFailsWith<ExecutionException> { run(engine) }
        assertEquals(1, actions.calls["seed-1"])
        actions.failAfter = null
        val resumed = engine.resume(temp.resolve("workspace"))
        assertEquals(WorkspaceState.WAITING_REVIEW, resumed.state)
        assertEquals(1, actions.calls["seed-1"], "An intact orphan publication is adopted without rerunning matching")
        assertEquals(1, resumed.stages.first().attempts.size)
        assertTrue(Files.isRegularFile(Path.of(resumed.stages.first().receiptPath!!)))
    }

    @Test fun `partial publication retains its attempt and resumes in a new directory`() {
        val (engine, actions) = fixture()
        actions.partial = "seed-1"
        assertFailsWith<ExecutionException> { run(engine) }
        val old = temp.resolve("workspace/stages/seed-1/attempt-001/published/knowledge.json")
        assertTrue(Files.isRegularFile(old))
        actions.partial = null
        val resumed = engine.resume(temp.resolve("workspace"))
        assertEquals(2, actions.calls["seed-1"])
        assertEquals(listOf("INCOMPLETE", "COMPLETE"), resumed.stages.first().attempts.map { it.state })
        assertTrue(Files.isRegularFile(old), "Failed partial output remains available for diagnosis")
        assertTrue(resumed.stages.first().receiptPath!!.contains("attempt-002"))
    }

    @Test fun `receipt written before progress update is adopted without reexecution`() {
        val (engine, actions) = fixture()
        actions.failAfter = "seed-1"
        assertFailsWith<ExecutionException> { run(engine) }
        val current = state()
        val seed = current.stages.first()
        val root = temp.resolve("workspace")
        val attempt = seed.attempts.single()
        val directory = root.resolve(attempt.path)
        val context = WorkspaceContext(root, current, emptyMap())
        val files = Files.walk(directory).use { paths -> paths.filter { Files.isRegularFile(it) }.map {
            WorkspaceFile(root.relativize(it).toString().replace('\\', '/'), Digests.file(it))
        }.toList().sortedBy { it.path } }
        writeWorkspaceJson(directory.resolve("receipt.json"), WorkspaceReceipt(workspaceId = current.workspaceId,
            stageId = seed.id, attempt = attempt.number, implementationId = current.inputs.implementationId,
            product = actions.validate(context, seed, directory), files = files))
        actions.failAfter = null
        engine.resume(temp.resolve("workspace"))
        assertEquals(1, actions.calls["seed-1"])
        assertNotNull(state().stages.first().receipt)
    }

    @Test fun `frozen review heads survive a publication crash and later review revision`() {
        val (engine, actions) = fixture()
        val waiting = run(engine)
        approve(waiting)
        actions.partial = "publish"
        assertFailsWith<ExecutionException> { engine.resume(temp.resolve("workspace")) }
        val frozen = state().stages.single { it.id == "review-heads" }
        assertNotNull(frozen.receipt)
        val dir = Path.of(waiting.runPath!!)
        val old = ReviewStore.latest(dir, "fixture-run").getValue("selected")
        ReviewStore.submit(dir, "fixture-run", "selected", old.revisionId, mapOf("action" to "DEFER"))
        actions.partial = null
        val complete = engine.resume(temp.resolve("workspace"))
        val output = Files.readString(Path.of(complete.knowledgePath!!))
        assertTrue(output.contains(old.revisionId), "Publication must use the previously frozen Review revision")
        assertFalse(output.contains(ReviewStore.latest(dir, "fixture-run").getValue("selected").revisionId))
        assertEquals(1, actions.calls["review-heads"])
    }

    @Test fun `inputs implementation and single writer lock prevent unsafe continuation`() {
        val (engine, actions) = fixture()
        run(engine)
        FileChannel.open(temp.resolve("workspace/.workspace.lock"), StandardOpenOption.WRITE).use { channel -> channel.lock().use {
            assertFailsWith<ValidationException> { engine.resume(temp.resolve("workspace")) }
        } }
        actions.buildId = "changed"
        assertFailsWith<ValidationException> { engine.resume(temp.resolve("workspace")) }
        actions.buildId = "fixture-implementation"
        Files.writeString(temp.resolve("input.bin"), "changed APK identity bytes")
        assertFailsWith<ValidationException> { engine.resume(temp.resolve("workspace")) }
    }

    @Test fun `receipt cannot omit a mapping file or redirect a completed product`() {
        val (engine, _) = fixture()
        run(engine)
        val current = state()
        val seed = current.stages.first()
        val path = temp.resolve("workspace").resolve(seed.receipt!!.path)
        val receipt = JsonFiles.read(path, WorkspaceReceipt::class.java)
        writeWorkspaceJson(path, receipt.copy(files = receipt.files.filterNot { it.path.endsWith("mapping.tiny") }))
        writeState(current.copy(stages = current.stages.mapIndexed { i, s -> if (i == 0) s.copy(receipt = s.receipt!!.copy(sha256 = Digests.file(path))) else s }))
        assertFailsWith<ValidationException> { engine.resume(temp.resolve("workspace")) }
        writeWorkspaceJson(path, receipt.copy(product = receipt.product.copy(knowledgePath = "inputs/profile.json")))
        writeState(current.copy(stages = current.stages.mapIndexed { i, s -> if (i == 0) s.copy(receipt = s.receipt!!.copy(sha256 = Digests.file(path))) else s }))
        assertFailsWith<ValidationException> { engine.resume(temp.resolve("workspace")) }
    }

    @Test fun `waiting dependencies halt before discovery and have no fabricated no match`() {
        val (engine, actions) = fixture(0)
        actions.discoveryDependencies = listOf("support.factory")
        val waiting = run(engine)
        assertEquals(WorkspaceState.WAITING_DEPENDENCY, waiting.state)
        assertNull(waiting.runPath)
        assertTrue(actions.calls.isEmpty())
        assertTrue(waiting.message!!.contains("support.factory"))
    }

    @Test fun `coordination COMPLETE cannot replace a publication receipt`() {
        val (engine, _) = fixture()
        run(engine)
        writeState(state().copy(state = WorkspaceState.COMPLETE))
        assertFailsWith<ValidationException> { engine.status(temp.resolve("workspace")) }
        assertFailsWith<ValidationException> { engine.resume(temp.resolve("workspace")) }
    }

    @Test fun `portable method artifact references resolve inside a moved package`() {
        val original = temp.resolve("old-package")
        Files.createDirectories(original.resolve("method-artifacts"))
        val file = original.resolve("method-artifacts/catalog.json")
        Files.writeString(file, "retained public metadata")
        val ref = ScenarioArtifactRef("fixture.catalog", "method-artifacts/catalog.json", Digests.file(file))
        fun report(value: ScenarioArtifactRef) = JsonObject().apply { add("methodArtifacts", JsonFiles.gson.toJsonTree(listOf(value))) }
        val moved = temp.resolve("moved-package")
        Files.move(original, moved)
        val resolved = AnalysisWorkspaceActions.artifactRefs(report(ref), moved).single()
        assertEquals(moved.resolve(ref.path).toString(), resolved.path)
        Digests.verify(Artifact(resolved.path, resolved.sha256))
        assertEquals(resolved, AnalysisWorkspaceActions.artifactRefs(report(resolved), moved).single(), "Legacy absolute in-package paths remain readable")
        assertFailsWith<ValidationException> { AnalysisWorkspaceActions.artifactRefs(report(ref.copy(path = "../outside.json")), moved) }
        assertFailsWith<ValidationException> { AnalysisWorkspaceActions.artifactRefs(report(ref.copy(path = temp.resolve("outside.json").toString())), moved) }
    }

    @Test fun `seed plan rejects missing cyclic wrong-kind and insufficient-round dependencies before execution`() {
        val file = Artifact("fixture-profile", "0".repeat(64))
        fun params(vararg pairs: Pair<String, Any>) = JsonFiles.gson.toJsonTree(pairs.toMap()).asJsonObject
        val profile = AnalysisProfile(id = "fixture-rpc", strategy = StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "factory")))
        val seed = AnalysisAnchorDefinition("seed", strategy = StrategySpec("messages.rpc-descriptor", params("service" to "fixture.Service", "rpc" to "Read"), EntityKind.METHOD))
        val descriptor = AnalysisAnchorDefinition("descriptor", strategy = StrategySpec("messages.rpc-related-type", params("role" to "descriptor"), requires = mapOf("descriptor" to "seed")))
        val factory = AnalysisAnchorDefinition("factory", strategy = StrategySpec("grpc-java.full-method-name", resultKind = EntityKind.METHOD, requires = mapOf("descriptor" to "descriptor")))
        fun plan(rounds: Int, anchors: List<AnalysisAnchorDefinition>) = AnalysisMethodPlan("messages.grpc", file, profile, file,
            List(rounds) { AnalysisRuleFile(anchors = anchors) }, listOf(file))
        val valid = listOf(seed, descriptor, factory)
        AnalysisWorkspaceActions.validateSeedPlan(plan(3, valid), null, "current-build")
        assertFailsWith<ValidationException> { AnalysisWorkspaceActions.validateSeedPlan(plan(2, valid), null, "current-build") }
        assertFailsWith<ValidationException> { AnalysisWorkspaceActions.validateSeedPlan(plan(3, listOf(descriptor, factory)), null, "current-build") }
        val cyclic = descriptor.copy(strategy = descriptor.strategy!!.copy(requires = mapOf("descriptor" to "factory")))
        assertFailsWith<ValidationException> { AnalysisWorkspaceActions.validateSeedPlan(plan(3, listOf(cyclic, factory)), null, "current-build") }
        val wrongKind = AnalysisAnchorDefinition("factory", locators = listOf(Locator("string-use", "factory")))
        assertFailsWith<ValidationException> { AnalysisWorkspaceActions.validateSeedPlan(plan(3, listOf(seed, descriptor, wrongKind)), null, "current-build") }
    }

    @Test fun `implementation fingerprint is identical for class directories and JARs with different timestamps`() {
        val classes = temp.resolve("classes")
        val name = "dev/dexlineage/analysis/Fixture.class"
        val file = classes.resolve(name)
        Files.createDirectories(file.parent)
        Files.write(file, byteArrayOf(1, 2, 3))
        fun archive(path: Path, time: Long) {
            ZipOutputStream(Files.newOutputStream(path)).use { zip ->
                zip.putNextEntry(ZipEntry(name).apply { this.time = time })
                zip.write(Files.readAllBytes(file)); zip.closeEntry()
                zip.putNextEntry(ZipEntry("META-INF/ignored.txt")); zip.write("not implementation".toByteArray()); zip.closeEntry()
            }
        }
        val first = temp.resolve("first.jar"); archive(first, 1_000_000L)
        val second = temp.resolve("second.jar"); archive(second, 9_000_000L)
        val expected = workspaceImplementationFingerprint(classes, "matching-build")
        assertEquals(expected, workspaceImplementationFingerprint(first, "matching-build"))
        assertEquals(expected, workspaceImplementationFingerprint(second, "matching-build"))
        assertNotEquals(expected, workspaceImplementationFingerprint(first, "different-matching-build"))
        Files.write(file, byteArrayOf(1, 2, 4))
        assertNotEquals(expected, workspaceImplementationFingerprint(classes, "matching-build"))
    }

    private inner class FakeActions(private val seedCount: Int) : WorkspaceActions {
        var buildId = "fixture-implementation"
        var failAfter: String? = null
        var partial: String? = null
        var discoveryDependencies: List<String> = emptyList()
        val calls = mutableMapOf<String, Int>()
        override fun implementationId() = buildId
        override fun inputs(methodId: String, configPath: Path): WorkspaceInputs {
            val apk = Digests.artifact(temp.resolve("input.bin"))
            val file = Digests.artifact(temp.resolve("profile.json"))
            val config = Digests.artifact(configPath)
            val profile = AnalysisProfile(id = "fixture", discovery = Locator("string-use", "signal"))
            val method = AnalysisMethodPlan(methodId, file, profile, null, List(seedCount) { AnalysisRuleFile() }, listOf(file))
            return WorkspaceInputs(config, WorkspaceConfig(apk = apk.path, profile = file.path), apk, null, emptyList(), method,
                listOf(apk, file, config), buildId, "fixture-engine")
        }
        override fun discoveryWaiting(context: WorkspaceContext) = discoveryDependencies
        override fun reviewGate(runDir: Path): WorkspaceReviewGate {
            val heads = ReviewStore.latest(runDir, "fixture-run")
            return WorkspaceReviewGate(listOf("invalid", "inherited", "selected"), if ("selected" in heads) emptyList() else listOf("selected"), emptyList())
        }
        private fun payload(context: WorkspaceContext, stage: WorkspaceStage) = mapOf("schemaVersion" to 4,
            "workspaceId" to context.record.workspaceId, "stage" to stage.id, "apk" to context.record.inputs.apk.sha256)
        override fun execute(context: WorkspaceContext, stage: WorkspaceStage, attempt: Path): WorkspaceProduct {
            calls[stage.id] = (calls[stage.id] ?: 0) + 1
            fun write(name: String, value: Any = payload(context, stage)) {
                val file = attempt.resolve(name); Files.createDirectories(file.parent); JsonFiles.writeNew(file, value)
            }
            when (stage.kind) {
                WorkspaceStageKind.SEED, WorkspaceStageKind.PUBLICATION -> {
                    if (stage.kind == WorkspaceStageKind.SEED) write("run/run.json")
                    val heads = context.products["review-heads"]?.reviewHeadsPath?.let { Files.readString(context.resolve(it)) } ?: "no reviews"
                    write("published/knowledge.json", payload(context, stage) + ("heads" to heads))
                    if (partial == stage.id) throw ExecutionException("Interrupted after only knowledge.json")
                    write("published/mapping.tiny"); write("published/report.json"); write("published/evidence/code.java")
                }
                WorkspaceStageKind.DISCOVERY -> { write("discovery/discovery.json"); write("discovery/rules.json") }
                WorkspaceStageKind.PREPARE -> write("run/run.json")
                WorkspaceStageKind.PACKET -> { write("packet/review-packet.json"); write("packet/summary.md"); write("packet/evidence/code.java") }
                WorkspaceStageKind.REVIEW_HEADS -> {
                    val heads = ReviewStore.latest(context.runDir(), "fixture-run").mapValues { it.value.revisionId }
                    write("review-heads.json", mapOf("schemaVersion" to 4, "runId" to "fixture-run", "reviewRevisions" to heads))
                }
            }
            if (failAfter == stage.id) throw ExecutionException("Interrupted after complete formal outputs")
            return validate(context, stage, attempt)
        }
        override fun validate(context: WorkspaceContext, stage: WorkspaceStage, attempt: Path): WorkspaceProduct {
            fun checked(name: String): String {
                val path = attempt.resolve(name)
                requireInput(Files.isRegularFile(path), "Missing formal output $name")
                return context.relative(path)
            }
            when (stage.kind) {
                WorkspaceStageKind.SEED, WorkspaceStageKind.PUBLICATION -> {
                    val k = checked("published/knowledge.json")
                    checked("published/mapping.tiny"); checked("published/report.json"); checked("published/evidence/code.java")
                    requireInput(Files.readString(context.resolve(k)).contains(context.record.inputs.apk.sha256), "Wrong APK output")
                    if (stage.kind == WorkspaceStageKind.PUBLICATION) {
                        val frozen = context.resolve(context.products.getValue("review-heads").reviewHeadsPath!!)
                        val heads = ReviewStore.fromSnapshot(context.runDir(), "fixture-run", frozen)
                        requireInput(heads.values.all { Files.readString(context.resolve(k)).contains(it.revisionId) }, "Publication used different review heads")
                    }
                    return WorkspaceProduct(runPath = if (stage.kind == WorkspaceStageKind.SEED) checked("run/run.json").substringBeforeLast('/') else context.relative(context.runDir()),
                        knowledgePath = k, knowledgeId = "fixture-knowledge-${stage.id}", runId = "fixture-run")
                }
                WorkspaceStageKind.DISCOVERY -> return WorkspaceProduct(discoveryPath = checked("discovery/discovery.json"), rulesPath = checked("discovery/rules.json"))
                WorkspaceStageKind.PREPARE -> return WorkspaceProduct(runPath = checked("run/run.json").substringBeforeLast('/'), runId = "fixture-run")
                WorkspaceStageKind.PACKET -> {
                    checked("packet/summary.md"); checked("packet/evidence/code.java")
                    return WorkspaceProduct(runPath = context.relative(context.runDir()), runId = "fixture-run", packetPath = checked("packet/review-packet.json").substringBeforeLast('/'),
                        selectedTaskIds = listOf("invalid", "inherited", "selected"))
                }
                WorkspaceStageKind.REVIEW_HEADS -> {
                    val path = checked("review-heads.json")
                    val heads = ReviewStore.fromSnapshot(context.runDir(), "fixture-run", context.resolve(path))
                    requireInput("selected" in heads, "Incomplete frozen review selection")
                    return WorkspaceProduct(runPath = context.relative(context.runDir()), runId = "fixture-run", reviewHeadsPath = path,
                        selectedTaskIds = listOf("invalid", "inherited", "selected"))
                }
            }
        }
    }
}
