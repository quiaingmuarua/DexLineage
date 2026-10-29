package dev.dexlineage.knowledge

import com.google.gson.JsonObject
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

/** Content-bound files, independent of Analysis and Migration task lifecycles. */
object EvidenceFiles {
    fun publish(directory: Path, runId: String, artifact: Artifact, refs: List<ClassRef>, code: List<DecompiledClass>): List<EvidenceRecord> {
        Digests.verify(artifact)
        val base = directory.resolve("evidence")
        Files.createDirectories(base)
        return refs.distinct().sortedBy { it.descriptor }.map { ref ->
            requireInput(ref.apkSha256 == artifact.sha256, "Evidence APK mismatch")
            val id = Identities.evidenceId(runId, ref)
            if (Files.exists(base.resolve(id))) return@map read(directory, runId, id)
            val source = code.singleOrNull { it.descriptor == ref.descriptor } ?: throw ExecutionException("Missing code for ${ref.descriptor}")
            val staging = Files.createTempDirectory(base, ".pending-")
            try {
                Files.writeString(staging.resolve("code.java"), source.javaCode)
                source.smaliCode?.let { Files.writeString(staging.resolve("code.smali"), it) }
                val record = EvidenceRecord(evidenceId = id, runId = runId, ref = ref,
                    javaPath = "evidence/$id/code.java", javaSha256 = Digests.file(staging.resolve("code.java")),
                    smaliPath = source.smaliCode?.let { "evidence/$id/code.smali" }, smaliSha256 = source.smaliCode?.let { Digests.file(staging.resolve("code.smali")) },
                    incomplete = source.incomplete, diagnostics = source.diagnostics, elapsedMillis = source.elapsedMillis)
                JsonFiles.writeNew(staging.resolve("record.json"), record)
                Files.move(staging, base.resolve(id), StandardCopyOption.ATOMIC_MOVE)
                record
            } finally { cleanStaging(staging, listOf("code.java", "code.smali", "record.json")) }
        }
    }

    fun read(directory: Path, runId: String, id: String): EvidenceRecord = checkedInput("evidence") {
        requireInput(id.matches(Regex("[a-f0-9]{64}")), "Invalid evidence ID")
        val e = JsonFiles.read(directory.resolve("evidence/$id/record.json"), EvidenceRecord::class.java)
        requireInput(e.runId == runId && e.evidenceId == id && id == Identities.evidenceId(runId, e.ref), "Evidence identity mismatch")
        verifyCode(directory, e.evidenceId, e.javaPath, e.javaSha256, e.smaliPath, e.smaliSha256)
        e
    }

    fun available(directory: Path, runId: String): List<EvidenceRecord> {
        val base = directory.resolve("evidence")
        if (!Files.isDirectory(base)) return emptyList()
        return Files.list(base).use { paths -> paths.filter { Files.isDirectory(it) && it.fileName.toString().matches(Regex("[a-f0-9]{64}")) }
            .map { read(directory, runId, it.fileName.toString()) }.toList().sortedBy { it.evidenceId } }
    }

    fun export(directory: Path, runId: String, id: String, output: Path): KnowledgeEvidence {
        val e = read(directory, runId, id)
        return KnowledgeFiles.copyEvidence(directory, output, KnowledgeEvidence(e.evidenceId, e.ref, e.javaPath, e.javaSha256, e.smaliPath, e.smaliSha256, e.incomplete, e.diagnostics))
    }
}

object KnowledgeFiles {
    fun id(value: VersionKnowledge): String = Digests.text(JsonFiles.encode(value.copy(knowledgeId = "")))

    fun read(path: Path): VersionKnowledge = checkedInput("version knowledge") {
        val value = JsonFiles.read(path, VersionKnowledge::class.java)
        requireInput(value.kind == "version-knowledge", "Not a VersionKnowledge document; use explicit S1 import for old data")
        requireInput(value.knowledgeId == id(value), "Knowledge fingerprint mismatch")
        validate(value)
        evidenceClosure(value).forEach {
            verifyCode(path.toAbsolutePath().parent, it.evidenceId, it.javaPath, it.javaSha256, it.smaliPath, it.smaliSha256)
        }
        value
    }

    fun write(output: Path, value: VersionKnowledge): VersionKnowledge {
        val normalized = value.copy(entries = value.entries.sortedBy { it.semanticId }, unresolved = value.unresolved.sortedBy { it.entry.semanticId },
            anchors = value.anchors.sortedBy { it.key }, knowledgeId = "")
        validate(normalized)
        evidenceClosure(normalized).forEach {
            verifyCode(output, it.evidenceId, it.javaPath, it.javaSha256, it.smaliPath, it.smaliSha256)
        }
        val published = normalized.copy(knowledgeId = id(normalized))
        JsonFiles.writeNew(output.resolve("knowledge.json"), published)
        return published
    }

    fun copyEvidence(sourceRoot: Path, output: Path, evidence: KnowledgeEvidence): KnowledgeEvidence {
        verifyCode(sourceRoot, evidence.evidenceId, evidence.javaPath, evidence.javaSha256, evidence.smaliPath, evidence.smaliSha256)
        val folder = output.resolve("evidence/${evidence.evidenceId}")
        Files.createDirectories(folder)
        copyOrVerify(sourceRoot.resolve(evidence.javaPath), output.resolve(evidence.javaPath), evidence.javaSha256)
        evidence.smaliPath?.let { copyOrVerify(sourceRoot.resolve(it), output.resolve(it), evidence.smaliSha256!!) }
        return evidence
    }

    fun evidenceClosure(value: Resolution): List<KnowledgeEvidence> = uniqueEvidence(value.dependencies.values.flatMap(::evidenceClosure))
    fun evidenceClosure(value: SupportAnchor): List<KnowledgeEvidence> = uniqueEvidence(value.evidence + evidenceClosure(value.resolution))
    fun evidenceClosure(value: KnowledgeEntry): List<KnowledgeEvidence> = uniqueEvidence(value.evidence + value.resolution?.let(::evidenceClosure).orEmpty())
    fun evidenceClosure(value: VersionKnowledge): List<KnowledgeEvidence> = uniqueEvidence(
        value.entries.flatMap(::evidenceClosure) + value.unresolved.flatMap { evidenceClosure(it.entry) } + value.anchors.flatMap(::evidenceClosure))

    fun copyEntry(sourceRoot: Path, output: Path, value: KnowledgeEntry): KnowledgeEntry {
        evidenceClosure(value).forEach { copyEvidence(sourceRoot, output, it) }; return value
    }
    fun copyAnchor(sourceRoot: Path, output: Path, value: SupportAnchor): SupportAnchor {
        evidenceClosure(value).forEach { copyEvidence(sourceRoot, output, it) }; return value
    }
    fun validateAnchor(anchor: SupportAnchor, apkSha256: String? = null) {
        RuleProofs.validateAnchor(anchor, apkSha256)
        requireInput(anchor.evidence.any { it.ref == anchor.binding.owner }, "Anchor requires owner code evidence")
        anchor.resolution.dependencies.values.forEach { validateAnchor(it, anchor.binding.owner.apkSha256) }
    }

    private fun uniqueEvidence(values: List<KnowledgeEvidence>): List<KnowledgeEvidence> {
        val grouped = values.groupBy { it.evidenceId }
        requireInput(grouped.values.all { it.distinct().size == 1 }, "Conflicting evidence references in proof closure")
        return grouped.toSortedMap().values.map { it.first() }
    }

    private fun validate(value: VersionKnowledge) = checkedInput("knowledge contents") {
        requireInput(value.schemaVersion == SCHEMA_VERSION && value.kind == "version-knowledge", "Unsupported knowledge format")
        val ids = value.entries.map { it.semanticId } + value.unresolved.map { it.entry.semanticId }
        requireInput(ids.distinct().size == ids.size, "Duplicate semantic identity in knowledge")
        requireInput(value.entries.map { it.binding.descriptor }.distinct().size == value.entries.size, "Duplicate current class binding")
        requireInput(value.entries.map { Identities.renamedFullName(it.binding.descriptor, it.name) }.distinct().size == value.entries.size, "Duplicate confirmed class name")
        requireInput(value.anchors.map { it.key }.distinct().size == value.anchors.size, "Duplicate anchor key")
        value.anchors.forEach { validateAnchor(it, value.artifact.sha256) }
        value.entries.forEach {
            requireInput(it.semanticId.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Confirmed knowledge requires semantic identity")
            requireInput(it.binding.apkSha256 == value.artifact.sha256, "Confirmed binding belongs to another APK")
            Identities.renamedFullName(it.binding.descriptor, it.name)
            val rule = it.ruleRevision ?: throw ValidationException("Confirmed knowledge requires a rule revision")
            val resolution = it.resolution ?: throw ValidationException("Confirmed knowledge requires a unique matching proof")
            RuleProofs.validate(rule)
            RuleProofs.validate(resolution)
            requireInput(rule.locators == it.locators && resolution.rule == rule, "Knowledge rule differs from its matching proof")
            requireInput(resolution.uniqueRef == it.binding, "Knowledge binding was not uniquely resolved")
            requireInput(it.evidence.any { evidence -> evidence.ref == it.binding }, "Confirmed knowledge requires owner code evidence")
            resolution.dependencies.values.forEach { anchor -> validateAnchor(anchor, value.artifact.sha256) }
        }
        value.unresolved.forEach {
            requireInput(it.entry.semanticId.isNotBlank() && it.sourceKnowledgeId.isNotBlank() && it.reason.isNotBlank(), "Unresolved knowledge requires its last confirmed source")
            Identities.requireDescriptor(it.entry.binding.descriptor)
        }
    }
}

/** Append-only single-writer journal. Payload meaning stays with its scenario owner. */
object ReviewStore {
    fun latest(directory: Path, runId: String): Map<String, StoredReview> =
        all(directory, runId).values.groupBy { it.taskId }.toSortedMap().mapValues { (id, records) -> head(id, records) }

    fun submit(directory: Path, runId: String, taskId: String, supersedes: String?, payload: Any): StoredReview =
        submitBatch(directory, runId, listOf(ReviewRequest(taskId, supersedes, payload))).single()

    /** One atomic transaction directory makes a batch visible together; no task claims or scheduler. */
    fun submitBatch(directory: Path, runId: String, requests: List<ReviewRequest>): List<StoredReview> {
        requireInput(requests.isNotEmpty() && requests.map { it.taskId }.distinct().size == requests.size, "Empty/duplicate review batch")
        val existing = all(directory, runId)
        val heads = existing.values.groupBy { it.taskId }.mapValues { (id, records) -> head(id, records) }
        val records = requests.map { request ->
            requireInput(request.taskId.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid task ID")
            val draft = StoredReview(revisionId = "", runId = runId, taskId = request.taskId,
                supersedes = request.supersedes, payload = JsonFiles.gson.toJsonTree(request.payload).asJsonObject)
            val record = draft.copy(revisionId = revisionId(draft))
            if (record.revisionId in existing) requireInput(existing.getValue(record.revisionId) == record, "Review digest collision")
            else requireInput(heads[request.taskId]?.revisionId == request.supersedes,
                "Review changed: specify supersedes=${heads[request.taskId]?.revisionId} for ${request.taskId}")
            record
        }
        val fresh = records.filter { it.revisionId !in existing }.sortedBy { it.taskId }
        if (fresh.isEmpty()) return records
        val draft = ReviewTransaction(transactionId = "", runId = runId, records = fresh)
        val transaction = draft.copy(transactionId = transactionId(draft))
        val base = directory.resolve("reviews")
        Files.createDirectories(base)
        val staging = Files.createTempDirectory(base, ".pending-")
        try {
            JsonFiles.writeNew(staging.resolve("transaction.json"), transaction)
            Files.move(staging, base.resolve(transaction.transactionId), StandardCopyOption.ATOMIC_MOVE)
        } finally { cleanStaging(staging, listOf("transaction.json")) }
        return records
    }

    /** Reproduce the exact review heads recorded by a previous publication. */
    fun fromSnapshot(directory: Path, runId: String, snapshotPath: Path): Map<String, StoredReview> = checkedInput("review snapshot") {
        val snapshot = com.google.gson.JsonParser.parseString(Files.readString(snapshotPath)).asJsonObject
        requireInput(snapshot["schemaVersion"]?.asInt == SCHEMA_VERSION && snapshot["runId"]?.asString == runId, "Publication snapshot belongs to another run")
        val heads = snapshot.getAsJsonObject("reviewRevisions") ?: throw ValidationException("Publication has no reviewRevisions")
        val records = all(directory, runId)
        heads.entrySet().associate { (task, value) ->
            val record = records[value.asString] ?: throw ValidationException("Unknown review revision: $value")
            requireInput(record.taskId == task, "Snapshot task/revision mismatch")
            task to record
        }.toSortedMap()
    }

    private fun all(directory: Path, runId: String): Map<String, StoredReview> = checkedInput("review journal") {
        val base = directory.resolve("reviews")
        if (!Files.isDirectory(base)) return@checkedInput emptyMap()
        val records = linkedMapOf<String, StoredReview>()
        Files.list(base).use { paths -> paths.filter { Files.isDirectory(it) && !it.fileName.toString().startsWith(".") }.sorted().forEach { path ->
            val transaction = JsonFiles.read(path.resolve("transaction.json"), ReviewTransaction::class.java)
            requireInput(transaction.runId == runId && transaction.transactionId == transactionId(transaction) && path.fileName.toString() == transaction.transactionId, "Review transaction identity mismatch")
            requireInput(transaction.records.isNotEmpty(), "Empty review transaction")
            transaction.records.forEach { record ->
                requireInput(record.runId == runId && record.revisionId == revisionId(record), "Review fingerprint mismatch")
                val previous = records.putIfAbsent(record.revisionId, record)
                requireInput(previous == null || previous == record, "Conflicting review history")
            }
        } }
        records.values.groupBy { it.taskId }.forEach { (task, items) -> head(task, items) }
        records
    }

    private fun head(taskId: String, records: List<StoredReview>): StoredReview {
        val byId = records.associateBy { it.revisionId }
        requireInput(records.count { it.supersedes == null } == 1, "Review journal has competing roots: $taskId")
        requireInput(records.filter { it.supersedes != null }.all { it.supersedes in byId }, "Review journal has missing history: $taskId")
        requireInput(records.filter { it.supersedes != null }.groupBy { it.supersedes }.values.none { it.size > 1 }, "Review journal has concurrent branches: $taskId")
        val replaced = records.mapNotNull { it.supersedes }.toSet()
        val head = records.singleOrNull { it.revisionId !in replaced } ?: throw ValidationException("Review journal has no unique head")
        val visited = mutableSetOf<String>()
        var cursor: StoredReview? = head
        while (cursor != null) { requireInput(visited.add(cursor.revisionId), "Review journal cycle"); cursor = cursor.supersedes?.let(byId::getValue) }
        requireInput(visited.size == records.size, "Review journal contains disconnected history")
        return head
    }
    private fun revisionId(record: StoredReview): String = Digests.text(JsonFiles.encode(record.copy(revisionId = "")))
    private fun transactionId(record: ReviewTransaction): String = Digests.text(JsonFiles.encode(record.copy(transactionId = "")))
}

/** Namespace invariants only; scenarios decide whether a claim has semantic support. */
object NameChecks {
    fun conflicts(renames: Map<String, AcceptedRename>, inventory: Set<String>, baselineNames: Map<String, String> = emptyMap()): Map<String, String> {
        val conflicts = sortedMapOf<String, String>()
        requireInput(baselineNames.keys.all { it in inventory }, "Baseline contains a class outside this APK")
        renames.forEach { (id, r) -> requireInput(r.descriptor in inventory, "Unknown target for $id"); r.newFullName.split('.').forEach { Identities.renamedFullName("Lx;", it) } }
        renames.entries.groupBy { it.value.descriptor }.values.filter { it.size > 1 }.flatten().forEach { conflicts[it.key] = "target_conflict" }
        while (true) {
            val remaining = renames.filterKeys { it !in conflicts }
            val byClass = remaining.entries.associateBy { it.value.descriptor }
            val groups = inventory.groupBy { descriptor -> byClass[descriptor]?.value?.newFullName ?: baselineNames[descriptor] ?: Identities.rawName(descriptor) }
            val before = conflicts.size
            groups.values.filter { it.size > 1 }.flatten().mapNotNull { byClass[it]?.key }.forEach { conflicts[it] = "name_conflict" }
            if (conflicts.size == before) return conflicts
        }
    }
}

private fun verifyCode(root: Path, id: String, javaPath: String, javaHash: String, smaliPath: String?, smaliHash: String?) {
    requireInput(id.matches(Regex("[a-f0-9]{64}")), "Invalid evidence ID")
    requireInput(javaPath == "evidence/$id/code.java" && (smaliPath == null || smaliPath == "evidence/$id/code.smali"), "Invalid evidence path")
    requireInput(Files.isRegularFile(root.resolve(javaPath)) && Digests.file(root.resolve(javaPath)) == javaHash, "Evidence Java content missing or changed: $id")
    if (smaliPath != null) requireInput(Files.isRegularFile(root.resolve(smaliPath)) && Digests.file(root.resolve(smaliPath)) == smaliHash, "Evidence Smali content missing or changed: $id")
    else requireInput(smaliHash == null, "Smali hash without file")
}
private fun copyOrVerify(source: Path, target: Path, hash: String) {
    if (Files.exists(target)) requireInput(Digests.file(target) == hash, "Evidence copy conflict: $target")
    else Files.copy(source, target)
}
private fun cleanStaging(path: Path, names: List<String>) {
    if (Files.exists(path)) { names.forEach { Files.deleteIfExists(path.resolve(it)) }; Files.deleteIfExists(path) }
}
