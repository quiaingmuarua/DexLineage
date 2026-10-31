package dev.dexlineage.analysis.workspace

import dev.dexlineage.io.*
import dev.dexlineage.model.SCHEMA_VERSION
import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.UUID

/** A finite on-disk coordinator for Analysis. Reviews remain in the Analysis run journal. */
object WorkspaceService {
    fun run(methodId: String, configPath: Path, workDir: Path): WorkspaceStatus = WorkspaceEngine(AnalysisWorkspaceActions).run(methodId, configPath, workDir)
    fun status(workDir: Path): WorkspaceStatus = WorkspaceEngine(AnalysisWorkspaceActions).status(workDir)
    fun resume(workDir: Path): WorkspaceStatus = WorkspaceEngine(AnalysisWorkspaceActions).resume(workDir)
}

/** Internal file/protocol seam for crash tests; this is not an extension or plugin interface. */
internal interface WorkspaceActions {
    fun inputs(methodId: String, configPath: Path): WorkspaceInputs
    fun implementationId(): String
    fun execute(context: WorkspaceContext, stage: WorkspaceStage, attempt: Path): WorkspaceProduct
    fun validate(context: WorkspaceContext, stage: WorkspaceStage, attempt: Path): WorkspaceProduct
    fun reviewGate(runDir: Path): WorkspaceReviewGate
    fun discoveryWaiting(context: WorkspaceContext): List<String>
}

internal data class WorkspaceContext(val root: Path, val record: WorkspaceRecord, val products: Map<String, WorkspaceProduct>) {
    fun resolve(relative: String): Path = confined(root, relative)
    fun relative(path: Path): String {
        val normalized = path.toAbsolutePath().normalize()
        requireInput(normalized.startsWith(root), "Workspace product escapes its root: $path")
        return root.relativize(normalized).toString().replace('\\', '/')
    }
    fun base(): Path? = record.stages.filter { it.kind == WorkspaceStageKind.SEED }.mapNotNull { products[it.id]?.knowledgePath }
        .lastOrNull()?.let(::resolve) ?: record.inputs.baseKnowledge?.let { Path.of(it.path) }
    fun runDir(): Path = products.values.lastOrNull { it.runPath != null && it.knowledgePath == null }?.runPath?.let(::resolve)
        ?: throw ValidationException("Workspace has no prepared Analysis run")
}

internal class WorkspaceEngine(private val actions: WorkspaceActions) {
    fun run(methodId: String, configPath: Path, directory: Path): WorkspaceStatus {
        val inputs = actions.inputs(methodId, configPath.toAbsolutePath().normalize())
        val root = directory.toAbsolutePath().normalize()
        createNewDirectory(root)
        return locked(root) {
            val record = WorkspaceRecord(workspaceId = identity(inputs), inputs = inputs, stages = stages(inputs.method.seedSteps.size))
            Files.createDirectory(root.resolve("inputs"))
            JsonFiles.writeNew(root.resolve("inputs/profile.json"), inputs.method.profile)
            inputs.method.seedSteps.forEachIndexed { index, rules -> JsonFiles.writeNew(root.resolve("inputs/seed-${index + 1}.json"), rules) }
            save(root, record)
            advance(root, record)
        }
    }

    fun resume(directory: Path): WorkspaceStatus {
        val root = directory.toAbsolutePath().normalize()
        requireInput(Files.isDirectory(root), "Workspace directory does not exist: $root")
        return locked(root) {
            val record = read(root)
            requireInput(record.inputs.implementationId == actions.implementationId(), "Workspace execution implementation changed; start a new workspace")
            record.inputs.inputFiles.forEach(Digests::verify)
            validateFrozenFiles(root, record)
            advance(root, record)
        }
    }

    /** No files, lock, receipts or stage outputs are created by status. */
    fun status(directory: Path): WorkspaceStatus {
        val root = directory.toAbsolutePath().normalize()
        val record = read(root)
        return summarize(root, record, products(root, record))
    }

    private fun advance(root: Path, initial: WorkspaceRecord): WorkspaceStatus {
        var record = initial
        val completed = products(root, record).toMutableMap()
        validateComplete(record, completed)
        if (record.state == WorkspaceState.COMPLETE) return summarize(root, record, completed)
        for (position in record.stages.indices) {
            var stage = record.stages[position]
            if (stage.receipt != null) continue
            var context = WorkspaceContext(root, record, completed)
            if (stage.kind == WorkspaceStageKind.DISCOVERY) {
                val waiting = actions.discoveryWaiting(context)
                if (waiting.isNotEmpty()) {
                    record = record.copy(state = WorkspaceState.WAITING_DEPENDENCY, message = "Discovery waits for anchors: ${waiting.joinToString()}")
                    save(root, record)
                    return summarize(root, record, completed)
                }
            }
            if (stage.kind == WorkspaceStageKind.PREPARE && completed.values.lastOrNull { it.discoveryPath != null }?.rulesPath == null) {
                record = record.copy(state = WorkspaceState.COMPLETE, message = "Discovery produced no executable target drafts")
                save(root, record)
                return summarize(root, record, completed)
            }
            if (stage.kind == WorkspaceStageKind.REVIEW_HEADS && stage.attempts.isEmpty()) {
                val gate = actions.reviewGate(context.runDir())
                if (gate.unreviewed.isNotEmpty() || gate.waiting.isNotEmpty()) {
                    record = record.copy(state = if (gate.waiting.isNotEmpty()) WorkspaceState.WAITING_DEPENDENCY else WorkspaceState.WAITING_REVIEW,
                        message = "Selected tasks require Review or resolved dependencies; submit Review to the prepared Analysis run, then resume")
                    save(root, record)
                    return summarize(root, record, completed)
                }
            }
            // A previous process may have finished all output writes before its atomic receipt.
            val prior = stage.attempts.lastOrNull()
            if (prior != null && prior.state == "STARTED") {
                val attemptDir = context.resolve(prior.path)
                val receiptPath = attemptDir.resolve("receipt.json")
                val adopted = if (Files.isRegularFile(receiptPath)) readReceipt(root, record, stage, prior, receiptPath)
                    else try {
                        val product = actions.validate(context, stage, attemptDir)
                        writeReceipt(root, record, stage, prior, product)
                    } catch (_: Exception) { null }
                if (adopted != null) {
                    requireInput(adopted.product == actions.validate(context, stage, attemptDir), "Receipt product differs from its stage inputs or complete outputs")
                    completed[stage.id] = adopted.product
                    stage = finish(root, stage, prior, receiptPath)
                    record = replace(record, position, stage)
                    save(root, record)
                    continue
                }
                stage = stage.copy(attempts = stage.attempts.dropLast(1) + prior.copy(state = "INCOMPLETE", error = "Prior attempt has no complete, valid output receipt"))
                record = replace(record, position, stage)
                save(root, record)
                context = WorkspaceContext(root, record, completed)
            }
            if (stage.kind == WorkspaceStageKind.REVIEW_HEADS) {
                val gate = actions.reviewGate(context.runDir())
                if (gate.unreviewed.isNotEmpty() || gate.waiting.isNotEmpty()) {
                    record = record.copy(state = if (gate.waiting.isNotEmpty()) WorkspaceState.WAITING_DEPENDENCY else WorkspaceState.WAITING_REVIEW,
                        message = "Selected tasks are not ready for a review snapshot")
                    save(root, record)
                    return summarize(root, record, completed)
                }
            }
            val number = (stage.attempts.maxOfOrNull { it.number } ?: 0) + 1
            val attempt = WorkspaceAttempt(number, "stages/${stage.id}/attempt-${number.toString().padStart(3, '0')}")
            val attemptDir = context.resolve(attempt.path)
            Files.createDirectories(attemptDir.parent)
            Files.createDirectory(attemptDir)
            stage = stage.copy(attempts = stage.attempts + attempt)
            record = replace(record, position, stage).copy(state = WorkspaceState.RUNNING, message = "Executing ${stage.id}, attempt $number")
            save(root, record)
            context = WorkspaceContext(root, record, completed)
            try {
                record.inputs.inputFiles.forEach(Digests::verify)
                actions.execute(context, stage, attemptDir)
                val product = actions.validate(context, stage, attemptDir)
                val receipt = writeReceipt(root, record, stage, attempt, product)
                completed[stage.id] = receipt.product
                record = replace(record, position, finish(root, stage, attempt, attemptDir.resolve("receipt.json")))
                save(root, record)
            } catch (failure: Exception) {
                // Keep STARTED: resume must inspect a possibly complete result before allocating another attempt.
                record = record.copy(state = WorkspaceState.FAILED, message = "${stage.id}: ${failure.message ?: failure.javaClass.simpleName}")
                save(root, record)
                throw failure
            }
        }
        record = record.copy(state = WorkspaceState.COMPLETE, message = null)
        save(root, record)
        return summarize(root, record, completed)
    }

    private fun summarize(root: Path, record: WorkspaceRecord, products: Map<String, WorkspaceProduct>): WorkspaceStatus {
        validateComplete(record, products)
        val run = products.values.lastOrNull { it.runPath != null && it.knowledgePath == null }?.runPath
        val gate = if (run != null && record.state != WorkspaceState.COMPLETE && products["review-heads"] == null)
            actions.reviewGate(confined(root, run)) else WorkspaceReviewGate(products["packet"]?.selectedTaskIds.orEmpty(), emptyList(), emptyList())
        val state = if (record.state in setOf(WorkspaceState.WAITING_REVIEW, WorkspaceState.WAITING_DEPENDENCY) && run != null) when {
            gate.waiting.isNotEmpty() -> WorkspaceState.WAITING_DEPENDENCY
            gate.unreviewed.isNotEmpty() -> WorkspaceState.WAITING_REVIEW
            else -> WorkspaceState.RUNNING
        } else record.state
        fun absolute(path: String?) = path?.let { confined(root, it).toString() }
        return WorkspaceStatus(workspaceId = record.workspaceId, methodId = record.inputs.method.methodId, state = state,
            workspacePath = root.toString(), runPath = absolute(run), packetPath = absolute(products["packet"]?.packetPath),
            knowledgePath = absolute(products["publish"]?.knowledgePath), discoveryPath = absolute(products["discover"]?.discoveryPath),
            reviewHeadsPath = absolute(products["review-heads"]?.reviewHeadsPath), selectedTaskIds = gate.selected,
            pendingTaskIds = gate.unreviewed, waitingTaskIds = gate.waiting,
            stages = record.stages.map { stage -> WorkspaceStageStatus(stage.id, stage.kind,
                if (stage.receipt != null) "COMPLETE" else stage.attempts.lastOrNull()?.state ?: "PENDING", stage.attempts,
                absolute(stage.receipt?.path), products[stage.id]) }, message = record.message)
    }

    private fun validateComplete(record: WorkspaceRecord, products: Map<String, WorkspaceProduct>) {
        if (record.state != WorkspaceState.COMPLETE) return
        val published = products["publish"]?.knowledgePath != null
        val discovery = products["discover"]
        val noDrafts = discovery?.discoveryPath != null && discovery.rulesPath == null && products["prepare"] == null
        requireInput(published || noDrafts, "Workspace COMPLETE requires a verified publication or a completed empty discovery")
    }

    private fun read(root: Path): WorkspaceRecord {
        val record = JsonFiles.read(root.resolve("workspace.json"), WorkspaceRecord::class.java)
        requireInput(record.kind == "analysis-workspace" && record.workspaceId == identity(record.inputs), "Workspace input identity changed")
        val expected = stages(record.inputs.method.seedSteps.size)
        requireInput(record.stages.map { Triple(it.id, it.kind, it.seedIndex) } == expected.map { Triple(it.id, it.kind, it.seedIndex) }, "Workspace stage plan changed")
        record.stages.forEach { stage ->
            requireInput(stage.attempts.map { it.number } == (1..stage.attempts.size).toList(), "Workspace attempt sequence changed")
            stage.attempts.forEach { a -> requireInput(a.path == "stages/${stage.id}/attempt-${a.number.toString().padStart(3, '0')}", "Invalid workspace attempt path") }
        }
        return record
    }

    private fun products(root: Path, record: WorkspaceRecord): Map<String, WorkspaceProduct> = buildMap {
        record.stages.forEach { stage -> stage.receipt?.let { reference ->
            val path = confined(root, reference.path)
            requireInput(Files.isRegularFile(path) && Digests.file(path) == reference.sha256, "Workspace receipt missing or changed: ${stage.id}")
            val attempt = stage.attempts.lastOrNull() ?: throw ValidationException("Receipt without a stage attempt")
            requireInput(reference.path == "${attempt.path}/receipt.json" && attempt.state == "COMPLETE", "Workspace completion record is inconsistent")
            val receipt = readReceipt(root, record, stage, attempt, path)
            val checked = actions.validate(WorkspaceContext(root, record, toMap()), stage, confined(root, attempt.path))
            requireInput(receipt.product == checked, "Workspace receipt product differs from its frozen stage inputs")
            put(stage.id, receipt.product)
        } }
    }

    private fun readReceipt(root: Path, record: WorkspaceRecord, stage: WorkspaceStage, attempt: WorkspaceAttempt, path: Path): WorkspaceReceipt {
        val receipt = JsonFiles.read(path, WorkspaceReceipt::class.java)
        requireInput(receipt.kind == "analysis-workspace-receipt" && receipt.workspaceId == record.workspaceId && receipt.stageId == stage.id &&
            receipt.attempt == attempt.number && receipt.implementationId == record.inputs.implementationId, "Workspace receipt identity mismatch")
        requireInput(receipt.files.isNotEmpty() && receipt.files.map { it.path }.distinct().size == receipt.files.size, "Empty or duplicate workspace receipt files")
        val folder = confined(root, attempt.path)
        receipt.files.forEach { file ->
            val output = confined(root, file.path)
            requireInput(output.startsWith(folder) && Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS) && Digests.file(output) == file.sha256,
                "Workspace output missing or changed: ${file.path}")
        }
        if (stage.kind != WorkspaceStageKind.PREPARE) requireInput(receipt.files == inventory(root, folder), "Workspace receipt omits or changes formal stage output files")
        return receipt
    }

    private fun writeReceipt(root: Path, record: WorkspaceRecord, stage: WorkspaceStage, attempt: WorkspaceAttempt, product: WorkspaceProduct): WorkspaceReceipt {
        val directory = confined(root, attempt.path)
        val files = inventory(root, directory)
        requireInput(files.isNotEmpty(), "Stage produced no durable artifacts: ${stage.id}")
        val receipt = WorkspaceReceipt(workspaceId = record.workspaceId, stageId = stage.id, attempt = attempt.number,
            implementationId = record.inputs.implementationId, product = product, files = files)
        writeWorkspaceJson(directory.resolve("receipt.json"), receipt)
        return receipt
    }

    private fun inventory(root: Path, directory: Path): List<WorkspaceFile> =
        Files.walk(directory).use { stream -> stream.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.filter { file ->
            val relative = directory.relativize(file)
            relative.none { it.toString() in setOf("work", "reviews") || it.toString().startsWith(".pending-") } && file.fileName.toString() != "receipt.json"
        }.map { file -> WorkspaceFile(root.relativize(file).toString().replace('\\', '/'), Digests.file(file)) }.toList().sortedBy { it.path } }

    private fun finish(root: Path, stage: WorkspaceStage, attempt: WorkspaceAttempt, receipt: Path) = stage.copy(
        attempts = stage.attempts.dropLast(1) + attempt.copy(state = "COMPLETE", error = null),
        receipt = WorkspaceFile(root.relativize(receipt).toString().replace('\\', '/'), Digests.file(receipt)))
    private fun replace(record: WorkspaceRecord, index: Int, value: WorkspaceStage) = record.copy(stages = record.stages.mapIndexed { i, stage -> if (i == index) value else stage })
    private fun save(root: Path, record: WorkspaceRecord) = writeWorkspaceJson(root.resolve("workspace.json"), record)
    private fun identity(inputs: WorkspaceInputs) = Digests.text(JsonFiles.encode(inputs))
    private fun stages(seedCount: Int): List<WorkspaceStage> = (0 until seedCount).map {
        WorkspaceStage("seed-${it + 1}", WorkspaceStageKind.SEED, it)
    } + listOf(WorkspaceStage("discover", WorkspaceStageKind.DISCOVERY), WorkspaceStage("prepare", WorkspaceStageKind.PREPARE),
        WorkspaceStage("packet", WorkspaceStageKind.PACKET), WorkspaceStage("review-heads", WorkspaceStageKind.REVIEW_HEADS), WorkspaceStage("publish", WorkspaceStageKind.PUBLICATION))
    private fun validateFrozenFiles(root: Path, record: WorkspaceRecord) {
        requireInput(Files.readString(root.resolve("inputs/profile.json")) == JsonFiles.encode(record.inputs.method.profile), "Frozen workspace profile changed")
        record.inputs.method.seedSteps.forEachIndexed { index, rules ->
            requireInput(Files.readString(root.resolve("inputs/seed-${index + 1}.json")) == JsonFiles.encode(rules), "Frozen workspace seed rules changed")
        }
    }
}

internal fun confined(root: Path, relative: String): Path {
    val result = root.resolve(relative).normalize()
    requireInput(!Path.of(relative).isAbsolute && result.startsWith(root), "Workspace path escapes its directory: $relative")
    return result
}

internal fun writeWorkspaceJson(path: Path, value: Any) {
    val temporary = path.resolveSibling(".pending-${path.fileName}-${UUID.randomUUID()}")
    try {
        JsonFiles.writeNew(temporary, value)
        FileChannel.open(temporary, StandardOpenOption.WRITE).use { it.force(true) }
        Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } finally { Files.deleteIfExists(temporary) }
}

private fun <T> locked(root: Path, action: () -> T): T = FileChannel.open(root.resolve(".workspace.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
    val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
    requireInput(lock != null, "Workspace is already in use by another writer: $root")
    lock!!.use { action() }
}
