package dev.dexlineage.migration

import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import dev.dexlineage.rules.RuleEngine
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.rules.RuleJson
import dev.dexlineage.rules.StrategyRegistry
import com.google.gson.JsonParser
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant

object MigrationService {
    fun prepare(knowledgePath: Path, sourceApkPath: Path, targetApkPath: Path, runDir: Path, minConfidence: Confidence = Confidence.HIGH,
                rulesPath: Path? = null, targetBasePath: Path? = null): MigrationRun {
        val knowledgeFile = Digests.artifact(knowledgePath)
        val knowledge = KnowledgeFiles.read(knowledgePath)
        val source = Digests.artifact(sourceApkPath)
        val target = Digests.artifact(targetApkPath)
        requireInput(source.sha256 == knowledge.artifact.sha256, "Source APK does not match VersionKnowledge")
        val orderedEntries = knowledge.entries.sortedBy { it.semanticId }
        requireInput(orderedEntries.all { it.semanticId.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) }, "Semantic IDs must be safe task IDs")
        val rulesFile = rulesPath?.let(Digests::artifact)
        val definitions = rulesPath?.let(::readRules) ?: MigrationRulesFile()
        val overrides = definitions.items
        val targetBaseFile = targetBasePath?.let(Digests::artifact)
        val targetBase = targetBasePath?.let(KnowledgeFiles::read)
        validateTargetBase(knowledge, target, targetBase)
        val rules = effectiveRules(knowledge, overrides, targetBase)
        val anchorRules = effectiveAnchorRules(knowledge, definitions.anchors, targetBase)
        validateDependencyDefinitions(rules.values.toList(), anchorRules)
        // Only frozen, current-APK anchors are available. New results wait for another publication/run.
        val available = targetBase?.anchors.orEmpty().filter { anchor ->
            anchor.rule == anchorRules[anchor.key] && anchor.resolution.engineBuildId == ResolutionEngine.buildId()
        }.associateBy { it.key }.let { current -> stableAnchors(current) }
        val inheritedEntries = targetBase?.entries.orEmpty().filter { entry ->
            entry.resolution?.let { reusable(it, rules.getValue(entry.semanticId), available, ResolutionEngine.buildId()) } == true
        }.associateBy { it.semanticId }
        val inheritedAnchors = available.filter { (_, anchor) -> reusable(anchor.resolution, anchor.rule, available, ResolutionEngine.buildId()) }
        createNewDirectory(runDir)
        try {
            val sourceScan = ApkReader.scan(sourceApkPath, emptySet())
            requireScan(sourceScan)
            orderedEntries.forEach { requireInput(sourceScan.classes[it.binding.descriptor] == it.binding.dexEntry, "Source binding absent from source APK: ${it.semanticId}") }
            knowledge.anchors.forEach { requireInput(sourceScan.classes[it.binding.owner.descriptor] == it.binding.owner.dexEntry, "Source anchor absent from source APK: ${it.key}") }
            val executing = rules.filterKeys { it !in inheritedEntries }.values + anchorRules.filterKeys { it !in inheritedAnchors }.values
            val query = ResolutionEngine.execute(target, executing.toList(), runDir.resolve("work/target"), available)
            requireScan(query.scan)
            targetBase?.entries?.forEach { requireInput(query.scan.classes[it.binding.descriptor] == it.binding.dexEntry, "Target base class is absent from target APK") }
            val tasks = orderedEntries.map { entry ->
                val rule = rules.getValue(entry.semanticId)
                val inherited = inheritedEntries[entry.semanticId]
                MigrationTask(entry.semanticId, entry, inherited?.resolution ?: query.resolutions[rule.revisionId], rule,
                    if (inherited == null) query.waiting[rule.revisionId].orEmpty() else emptyList(), inherited)
            }
            val anchorTasks = anchorRules.map { (key, rule) ->
                val inherited = inheritedAnchors[key]
                MigrationAnchorTask(key, rule, inherited?.resolution ?: query.resolutions[rule.revisionId],
                    if (inherited == null) query.waiting[rule.revisionId].orEmpty() else emptyList(), inherited)
            }
            (listOf(source, target, knowledgeFile) + listOfNotNull(rulesFile, targetBaseFile)).forEach(Digests::verify)
            var run = MigrationRun(runId = "", knowledgeFile = knowledgeFile, knowledge = knowledge, sourceApk = source, targetApk = target,
                minConfidence = minConfidence, tasks = tasks, sourceInventory = sourceScan.classes.toSortedMap(), targetInventory = query.scan.classes.toSortedMap(),
                sourceScan = sourceScan.stats, targetScan = query.scan.stats, analysisDiagnostics = query.analysis?.diagnostics.orEmpty(), analysisMillis = query.analysis?.elapsedMillis ?: 0,
                createdAt = Instant.now().toString(), rulesFile = rulesFile, ruleOverrides = overrides.sortedBy { it.semanticId }, engineBuildId = ResolutionEngine.buildId(),
                targetBaseFile = targetBaseFile, targetBase = targetBase, anchorTasks = anchorTasks, anchorOverrides = definitions.anchors.sortedBy { it.key })
            run = run.copy(runId = run.fingerprint())
            query.analysis?.code?.let { code ->
                val refs = code.mapNotNull { c -> run.targetInventory[c.descriptor]?.let { ClassRef(target.sha256, c.descriptor, it) } }
                EvidenceFiles.publish(runDir, run.runId, target, refs, code)
            }
            JsonFiles.writeNew(runDir.resolve("run.json"), run)
            return run
        } catch (e: Exception) {
            if (!Files.exists(runDir.resolve("failure.json"))) JsonFiles.writeNew(runDir.resolve("failure.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "operation" to "migration.prepare", "message" to (e.message ?: e.javaClass.name)))
            throw e
        }
    }

    fun readRun(dir: Path, verifyInputs: Boolean = true): MigrationRun = checkedInput("migration run") {
        val run = JsonFiles.read(dir.resolve("run.json"), MigrationRun::class.java)
        requireInput(run.kind == "migration-run" && run.toolVersion == TOOL_VERSION && run.jadxVersion == JADX_VERSION, "Unsupported migration run")
        requireInput(run.runId == run.fingerprint(), "Migration run fingerprint mismatch")
        requireInput(run.sourceScan.diagnostics.isEmpty() && run.targetScan.diagnostics.isEmpty(), "Incomplete migration scan")
        requireInput(run.tasks.map { it.taskId }.distinct().size == run.tasks.size, "Duplicate migration tasks")
        requireInput(run.sourceApk.sha256 == run.knowledge.artifact.sha256 && run.knowledge.knowledgeId == KnowledgeFiles.id(run.knowledge), "Run source knowledge identity mismatch")
        requireInput(run.tasks.map { it.entry }.sortedBy { it.semanticId } == run.knowledge.entries.sortedBy { it.semanticId }, "Run tasks differ from frozen knowledge")
        validateTargetBase(run.knowledge, run.targetApk, run.targetBase)
        requireInput((run.targetBase == null) == (run.targetBaseFile == null), "Incomplete target base snapshot")
        val rules = effectiveRules(run.knowledge, run.ruleOverrides, run.targetBase)
        val anchorRules = effectiveAnchorRules(run.knowledge, run.anchorOverrides, run.targetBase)
        validateDependencyDefinitions(rules.values.toList(), anchorRules)
        requireInput(run.ruleOverrides.isEmpty() && run.anchorOverrides.isEmpty() || run.rulesFile != null, "Rule overrides lack an input artifact")
        val available = stableAnchors(run.targetBase?.anchors.orEmpty().filter { it.rule == anchorRules[it.key] && it.resolution.engineBuildId == run.engineBuildId }.associateBy { it.key })
        fun checkExecution(rule: RuleRevision, proof: Resolution?, waiting: List<String>) {
            if (proof == null) requireInput(waiting.isNotEmpty() && waiting == rule.requires.values.filter { it !in available }.distinct().sorted(), "Waiting task lacks the exact missing dependency set")
            else {
                requireInput(waiting.isEmpty(), "Resolved task is also waiting")
                RuleProofs.validate(proof)
                requireInput(proof.rule == rule && proof.engineBuildId == run.engineBuildId && proof.apkSha256 == run.targetApk.sha256, "Resolution rule/engine/APK mismatch")
                requireInput(proof.dependencies == rule.requires.mapValues { (_, key) -> available[key] ?: throw ValidationException("Resolution used a non-frozen dependency") }, "Resolution dependency snapshot differs from target base")
                proof.matches.forEach { match ->
                    requireInput(run.targetInventory[match.owner.descriptor] == match.owner.dexEntry, "Resolution fact class/DEX identity mismatch")
                    requireInput((match.relatedRefs + match.trace.map { it.owner }).all { it.apkSha256 == run.targetApk.sha256 && run.targetInventory[it.descriptor] == it.dexEntry }, "Foreign relation evidence")
                }
            }
        }
        run.tasks.forEach { task ->
            requireInput(task.taskId == task.entry.semanticId && run.sourceInventory[task.entry.binding.descriptor] == task.entry.binding.dexEntry, "Invalid task source identity")
            requireInput(task.rule == rules.getValue(task.taskId), "Task differs from effective rule revision")
            checkExecution(task.rule, task.resolution, task.waitingFor)
            task.inheritedEntry?.let { inherited -> requireInput(run.targetBase?.entries?.singleOrNull { it.semanticId == task.taskId } == inherited && inherited.resolution == task.resolution && reusable(task.resolution!!, task.rule, available, run.engineBuildId), "Invalid inherited migration target") }
        }
        requireInput(run.anchorTasks.map { it.key }.toSet() == anchorRules.keys && run.anchorTasks.map { it.key }.distinct().size == run.anchorTasks.size, "Anchor task set differs from frozen definitions")
        run.anchorTasks.forEach { task ->
            requireInput(task.rule == anchorRules[task.key], "Anchor rule differs from definition")
            checkExecution(task.rule, task.resolution, task.waitingFor)
            task.inheritedAnchor?.let { requireInput(available[task.key] == it && it.resolution == task.resolution, "Invalid inherited anchor") }
        }
        if (verifyInputs) {
            (listOf(run.sourceApk, run.targetApk, run.knowledgeFile) + listOfNotNull(run.rulesFile, run.targetBaseFile)).forEach(Digests::verify)
            run.rulesFile?.let { val file = readRules(Path.of(it.path)); requireInput(file.items.sortedBy { item -> item.semanticId } == run.ruleOverrides && file.anchors.sortedBy { anchor -> anchor.key } == run.anchorOverrides, "Rule input differs from frozen overrides") }
            requireInput(KnowledgeFiles.read(Path.of(run.knowledgeFile.path)) == run.knowledge, "Frozen knowledge differs from input bundle")
            run.targetBaseFile?.let { requireInput(KnowledgeFiles.read(Path.of(it.path)) == run.targetBase, "Frozen target base differs from input bundle") }
        }
        run
    }

    fun tasks(dir: Path, state: String? = "UNREVIEWED", offset: Int = 0, limit: Int = 20): MigrationTasksPage {
        val run = readRun(dir)
        requireInput(offset >= 0 && limit > 0, "Expected non-negative offset and positive limit")
        val executionFilter = (state ?: "").uppercase().takeIf { requested -> MigrationExecutionState.entries.any { it.name == requested } }
        val requested = when (val normalized = (state ?: "UNREVIEWED").uppercase()) {
            "ALL" -> null
            else -> if (executionFilter != null) null else checkedInput("task state") { TaskState.valueOf(normalized) }
        }
        val decisions = currentDecisions(dir, run).associateBy { it.taskId }
        val evidence = EvidenceFiles.available(dir, run.runId)
        val views = run.tasks.sortedBy { it.taskId }.map { task ->
            val decision = decisions.getValue(task.taskId)
            val allowed = DecisionPolicy.allowedEvidence(run, task)
            MigrationTaskView(task.taskId, task.entry.name, decision.state, decision.reason, task.entry.binding, task.entry.captures,
                task.resolution, decision.revisionId, evidence.filter { it.ref in allowed }.map { it.evidenceId }, task.executionState, task.waitingFor)
        }.filter { (requested == null || it.state == requested) && (executionFilter == null || it.executionState.name == executionFilter) }
        return MigrationTasksPage(runId = run.runId, total = views.size, offset = offset, limit = limit, tasks = views.drop(offset).take(limit), carriedUnresolved = run.knowledge.unresolved, anchors = run.anchorTasks)
    }

    fun inspect(dir: Path, taskIds: Set<String>, selection: Map<String, Set<String>> = emptyMap()): List<EvidenceRecord> {
        val run = readRun(dir)
        requireInput(taskIds.isNotEmpty() && taskIds.all { id -> run.tasks.any { it.taskId == id } || run.anchorTasks.any { "anchor:${it.key}" == id } }, "Unknown or empty migration task IDs")
        requireInput(selection.keys.all { it in taskIds && !it.startsWith("anchor:") }, "Selections must belong to requested class tasks")
        val requestedTasks = run.tasks.filter { it.taskId in taskIds }
        val refs = linkedSetOf<ClassRef>()
        requestedTasks.forEach { task ->
            refs += task.entry.binding
            refs += KnowledgeFiles.evidenceClosure(task.entry).filter { it.ref.apkSha256 == run.sourceApk.sha256 }.map { it.ref }
            task.resolution?.let { refs += KnowledgeFiles.evidenceClosure(it).filter { e -> e.ref.apkSha256 == run.targetApk.sha256 }.map { e -> e.ref } }
            val chosen = selection[task.taskId]
            if (chosen != null) requireInput(chosen.all { d -> task.candidates.any { it.ref.descriptor == d } }, "Non-candidate inspect selection")
            task.candidates.filter { chosen == null || it.ref.descriptor in chosen }.forEach { candidate ->
                refs += candidate.ref
                refs += candidate.matches.flatMap { it.relatedRefs }
                refs += candidate.matches.flatMap { fact -> fact.trace.map { it.owner } }
                candidate.matches.mapNotNull { it.field?.call?.declaringType }.forEach { factory -> run.targetInventory[factory]?.let { refs += ClassRef(run.targetApk.sha256, factory, it) } }
            }
        }
        run.anchorTasks.filter { "anchor:${it.key}" in taskIds }.forEach { task -> task.resolution?.let { refs += proofRefs(it, run.targetInventory) } }
        val available = EvidenceFiles.available(dir, run.runId).associateBy { it.ref }
        val missing = refs.filter { it !in available }.toMutableSet()
        val sourceRoot = Path.of(run.knowledgeFile.path).parent
        val carried = requestedTasks.flatMap { KnowledgeFiles.evidenceClosure(it.entry) }.filter { it.ref in missing && it.ref.apkSha256 == run.sourceApk.sha256 }.distinctBy { it.ref }
        if (carried.isNotEmpty()) {
            KnowledgeFiles.read(Path.of(run.knowledgeFile.path))
            val code = carried.map { e -> DecompiledClass(e.ref.descriptor, Files.readString(sourceRoot.resolve(e.javaPath)), e.smaliPath?.let { Files.readString(sourceRoot.resolve(it)) }, e.incomplete, e.diagnostics, 0) }
            EvidenceFiles.publish(dir, run.runId, run.sourceApk, carried.map { it.ref }, code)
            missing.removeAll(carried.map { it.ref }.toSet())
        }
        for (artifact in listOf(run.sourceApk, run.targetApk).distinctBy { it.sha256 }) {
            val batch = missing.filter { it.apkSha256 == artifact.sha256 }
            if (batch.isEmpty()) continue
            Digests.verify(artifact)
            val code = ApkReader.decompile(Path.of(artifact.path), batch.map { it.descriptor }.toSet(), dir.resolve("work/inspect/${artifact.sha256}"))
            EvidenceFiles.publish(dir, run.runId, artifact, batch, code)
        }
        listOf(run.sourceApk, run.targetApk, run.knowledgeFile).forEach(Digests::verify)
        return refs.map { EvidenceFiles.read(dir, run.runId, Identities.evidenceId(run.runId, it)) }.sortedBy { it.evidenceId }
    }

    fun submit(dir: Path, reviewFile: Path): MigrationSubmission {
        val run = readRun(dir)
        rejectLegacyReviewFields(reviewFile)
        val batch = JsonFiles.read(reviewFile, MigrationReviewBatch::class.java)
        checkedInput("migration review batch") {
            requireInput(batch.runId == run.runId && batch.sourceKnowledgeId == run.knowledge.knowledgeId, "Review belongs to another run or knowledge revision")
            requireInput(batch.sourceApkSha256 == run.sourceApk.sha256 && batch.targetApkSha256 == run.targetApk.sha256, "Review APK identity mismatch")
            requireInput(batch.items.map { it.taskId }.distinct().size == batch.items.size, "Duplicate review tasks")
            requireInput(batch.items.isNotEmpty(), "Empty review batch")
            val evidence = EvidenceFiles.available(dir, run.runId).associateBy { it.evidenceId }
            batch.items.forEach { review ->
                val task = run.tasks.singleOrNull { it.taskId == review.taskId } ?: throw ValidationException("Unknown task: ${review.taskId}")
                DecisionPolicy.validateReview(run, task, review, evidence)
            }
        }
        val revisions = ReviewStore.submitBatch(dir, run.runId, batch.items.sortedBy { it.taskId }.map { ReviewRequest(it.taskId, it.supersedes, it) })
            .associate { it.taskId to it.revisionId }
        return MigrationSubmission(runId = run.runId, revisions = revisions, decisions = currentDecisions(dir, run))
    }

    fun publish(dir: Path, out: Path, reviewSnapshot: Path? = null): MigrationPublication {
        val run = readRun(dir)
        val reviews = if (reviewSnapshot == null) ReviewStore.latest(dir, run.runId) else ReviewStore.fromSnapshot(dir, run.runId, reviewSnapshot)
        val decisions = decisions(dir, run, reviews)
        val sourceRoot = Path.of(run.knowledgeFile.path).parent
        val targetBaseRoot = run.targetBaseFile?.let { Path.of(it.path).parent }
        KnowledgeFiles.read(Path.of(run.knowledgeFile.path))
        val exportableAnchors = run.anchorTasks.filter { it.resolution?.status == ResolutionStatus.UNIQUE && it.inheritedAnchor == null }
        ensureTargetEvidence(dir, run, exportableAnchors.flatMap { proofRefs(it.resolution!!, run.targetInventory) }.toSet())
        createNewDirectory(out)
        val entries = run.targetBase?.entries.orEmpty().associateBy { it.semanticId }.toMutableMap()
        val updatedIds = decisions.filter { it.state == TaskState.ACCEPTED && it.reason != "inherited_confirmed" }.map { it.taskId }.toSet()
        entries.values.filter { it.semanticId !in updatedIds }.forEach { KnowledgeFiles.copyEntry(targetBaseRoot!!, out, it) }
        val unresolved = run.knowledge.unresolved.map { old -> old.copy(entry = copyEntry(old.entry, sourceRoot, out)) }.toMutableList()
        for (decision in decisions) {
            val task = run.tasks.single { it.taskId == decision.taskId }
            if (decision.reason == "inherited_confirmed") continue
            if (decision.state == TaskState.ACCEPTED) {
                val review = decision.review!!
                val resolution = task.resolution!!
                val ids = review.evidenceIds.distinct().sorted()
                val evidence = ids.map { EvidenceFiles.export(dir, run.runId, it, out) }
                copyDependencies(resolution, targetBaseRoot, out)
                entries[task.taskId] = task.entry.copy(binding = decision.target!!, evidence = evidence, rationale = review.identityReason,
                    captures = RuleProofs.captures(resolution), locators = resolution.rule.locators,
                    ruleRevision = resolution.rule, resolution = resolution,
                    provenance = "migration:${run.runId}:${decision.revisionId}")
            } else if (task.taskId !in entries) {
                val explanation = decision.review?.let { "${decision.reason}: ${it.identityReason}" } ?: decision.reason
                unresolved += UnresolvedKnowledge(copyEntry(task.entry, sourceRoot, out), run.knowledge.knowledgeId, explanation, dir.toAbsolutePath().normalize().toString())
            }
        }
        val anchors = run.targetBase?.anchors.orEmpty().associateBy { it.key }.toMutableMap()
        anchors.values.filter { old -> exportableAnchors.none { it.key == old.key } }.forEach { KnowledgeFiles.copyAnchor(targetBaseRoot!!, out, it) }
        for (task in exportableAnchors) {
            val proof = task.resolution!!
            val refs = proofRefs(proof, run.targetInventory)
            val evidence = refs.sortedBy { it.descriptor }.map { EvidenceFiles.export(dir, run.runId, Identities.evidenceId(run.runId, it), out) }
            copyDependencies(proof, targetBaseRoot, out)
            anchors[task.key] = SupportAnchor(task.key, proof.uniqueEntity!!, task.rule, proof, evidence)
        }
        val knowledge = KnowledgeFiles.write(out, VersionKnowledge(knowledgeId = "", artifact = run.targetApk, entries = entries.values.toList(), unresolved = unresolved,
            provenance = "migration:${run.runId}", parentKnowledgeId = run.targetBase?.knowledgeId ?: run.knowledge.knowledgeId,
            anchors = anchors.values.toList(), migrationSourceKnowledgeId = run.knowledge.knowledgeId))
        MappingOutput.write(out.resolve("mapping.tiny"), knowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        val cachedEvidence = EvidenceFiles.available(dir, run.runId)
        val javaPaths = cachedEvidence.map { dir.resolve(it.javaPath) }.distinct()
        val smaliPaths = cachedEvidence.mapNotNull { it.smaliPath?.let(dir::resolve) }.distinct()
        val evidenceMetrics = mapOf("scope" to "emitted_or_cached_evidence", "agentReadsMeasured" to false,
            "ownerApkPairs" to cachedEvidence.map { it.ref.apkSha256 to it.ref.descriptor }.distinct().size,
            "apkCount" to cachedEvidence.map { it.ref.apkSha256 }.distinct().size,
            "javaFiles" to javaPaths.size, "javaLines" to javaPaths.sumOf { Files.lines(it).use { lines -> lines.count() } }, "javaBytes" to javaPaths.sumOf(Files::size),
            "smaliFiles" to smaliPaths.size, "smaliLines" to smaliPaths.sumOf { Files.lines(it).use { lines -> lines.count() } }, "smaliBytes" to smaliPaths.sumOf(Files::size),
            "incompleteClasses" to cachedEvidence.count { it.incomplete })
        JsonFiles.writeNew(out.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "migration-report", "runId" to run.runId,
            "sourceKnowledgeId" to run.knowledge.knowledgeId, "knowledgeId" to knowledge.knowledgeId, "sourceApk" to run.sourceApk, "targetApk" to run.targetApk,
            "reviewRevisions" to reviews.mapValues { it.value.revisionId }, "evidenceMetrics" to evidenceMetrics,
            "engineBuildId" to run.engineBuildId, "rulesFile" to run.rulesFile, "ruleOverrides" to run.ruleOverrides,
            "targetBaseFile" to run.targetBaseFile, "targetBaseKnowledgeId" to run.targetBase?.knowledgeId, "anchors" to run.anchorTasks,
            "anchorOverrides" to run.anchorOverrides, "resolvedAnchors" to knowledge.anchors.size,
            "resolutions" to ResolutionStatus.entries.associateWith { state -> run.tasks.count { it.resolution?.status == state } },
            "executionStates" to MigrationExecutionState.entries.associateWith { state -> run.tasks.count { it.executionState == state } },
            "sourceScan" to run.sourceScan, "targetScan" to run.targetScan, "analysisMillis" to run.analysisMillis, "analysisDiagnostics" to run.analysisDiagnostics,
            "tasks" to run.tasks, "decisions" to decisions, "carriedUnresolved" to run.knowledge.unresolved.size, "accepted" to entries.size, "unresolved" to unresolved.size,
            "acceptedUpdates" to updatedIds.size, "inheritedConfirmed" to run.tasks.count { it.inheritedEntry != null },
            "retainedAfterFailedUpdate" to run.tasks.filter { it.taskId in entries && it.taskId !in updatedIds && it.inheritedEntry == null }.map { it.taskId },
            "counts" to mapOf("tasks" to run.tasks.size, "candidates" to run.tasks.sumOf { it.candidates.size },
                "matches" to MatchStatus.entries.associateWith { state -> run.tasks.sumOf { task -> task.matches.count { it.status == state } } },
                "conditions" to MatchStatus.entries.associateWith { state -> run.tasks.sumOf { task -> task.matches.sumOf { m -> m.factors.count { it.status == state } } } },
                "reviews" to TaskState.entries.associateWith { state -> decisions.count { it.state == state } })))
        return MigrationPublication(runId = run.runId, knowledgeId = knowledge.knowledgeId, outputDirectory = out.toAbsolutePath().toString(), accepted = entries.size, unresolved = unresolved.size, decisions = decisions)
    }

    internal fun currentDecisions(dir: Path, run: MigrationRun): List<MigrationDecision> = decisions(dir, run, ReviewStore.latest(dir, run.runId))
    private fun decisions(dir: Path, run: MigrationRun, latest: Map<String, StoredReview>): List<MigrationDecision> = checkedInput("migration review history") {
        val reviews = latest.mapValues { (_, stored) -> stored.revisionId to JsonFiles.gson.fromJson(stored.payload, MigrationReview::class.java) }
        val evidence = EvidenceFiles.available(dir, run.runId).associateBy { it.evidenceId }
        DecisionPolicy.decide(run, reviews, evidence)
    }
    internal fun readRules(path: Path): MigrationRulesFile = checkedInput("migration rules file") {
        val raw = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(raw.keySet().all { it in setOf("schemaVersion", "items", "anchors") }, "Unknown migration rules file property")
        val items = raw.get("items")
        requireInput(items != null && items.isJsonArray, "Migration rules require an items array")
        items.asJsonArray.forEach { element ->
            requireInput(element.isJsonObject, "Migration rule item must be an object")
            val item = element.asJsonObject
            requireInput(item.keySet().all { it in setOf("semanticId", "locators", "expectedRevision", "strategy") }, "Unknown migration rule item property")
            val semanticId = item.get("semanticId")
            requireInput(semanticId != null && semanticId.isJsonPrimitive && semanticId.asJsonPrimitive.isString, "Migration rule semanticId must be a string")
            item.get("expectedRevision")?.takeUnless { it.isJsonNull }?.let { requireInput(it.isJsonPrimitive && it.asJsonPrimitive.isString, "expectedRevision must be a string") }
            validateRuleJson(item)
        }
        raw["anchors"]?.let { anchors ->
            requireInput(anchors.isJsonArray, "Anchor definitions must be an array")
            anchors.asJsonArray.forEach { element ->
                requireInput(element.isJsonObject, "Anchor definition must be an object")
                val item = element.asJsonObject
                requireInput(item.keySet().all { it in setOf("key", "locators", "strategy", "expectedRevision") }, "Unknown anchor definition property")
                requireInput(item["key"]?.isJsonPrimitive == true && item["key"].asJsonPrimitive.isString, "Anchor key must be a string")
                item["expectedRevision"]?.takeUnless { it.isJsonNull }?.let { requireInput(it.isJsonPrimitive && it.asJsonPrimitive.isString, "expectedRevision must be a string") }
                validateRuleJson(item)
            }
        }
        JsonFiles.read(path, MigrationRulesFile::class.java)
    }
    internal fun effectiveRules(knowledge: VersionKnowledge, overrides: List<MigrationRuleOverride>, targetBase: VersionKnowledge? = null): Map<String, RuleRevision> = checkedInput("migration rule overrides") {
        requireInput(overrides.map { it.semanticId }.distinct().size == overrides.size, "Duplicate rule override targets")
        val entries = knowledge.entries.associateBy { it.semanticId }
        overrides.forEach { change ->
            val entry = entries[change.semanticId] ?: throw ValidationException("Rule override adds unknown semantic target: ${change.semanticId}")
            requireInput(change.expectedRevision == null || change.expectedRevision == entry.ruleRevision?.revisionId, "Rule override expectedRevision does not match source knowledge")
            val rule = RuleProofs.revision(change.locators, change.strategy)
            requireInput(rule.resultKind == EntityKind.CLASS, "Rename rule must return a class")
            StrategyRegistry.validate(rule)
        }
        val changes = overrides.associateBy { it.semanticId }
        entries.mapValues { (id, entry) ->
            val revision = changes[id]?.let { RuleProofs.revision(it.locators, it.strategy) }
                ?: targetBase?.entries?.singleOrNull { it.semanticId == id }?.ruleRevision
                ?: requireNotNull(entry.ruleRevision) { "Missing current rule revision" }
            RuleProofs.validate(revision)
            requireInput(revision.resultKind == EntityKind.CLASS, "Migration rename rule must return a class")
            StrategyRegistry.validate(revision)
            revision
        }.toSortedMap()
    }
    private fun rejectLegacyReviewFields(path: Path) = checkedInput("migration review fields") {
        val raw = JsonParser.parseString(Files.readString(path)).asJsonObject
        raw.getAsJsonArray("items")?.forEach { item ->
            val obj = item.asJsonObject
            requireInput(listOf("targetDescriptor", "candidateComparisons", "name", "alias", "semanticName").none(obj::has),
                "Migration Review cannot select an entity, compare away candidates, or change the name; bind resolutionId and ruleRevisionId")
        }
    }
    internal fun effectiveAnchorRules(knowledge: VersionKnowledge, overrides: List<MigrationAnchorOverride>, targetBase: VersionKnowledge? = null): Map<String, RuleRevision> = checkedInput("migration anchor definitions") {
        requireInput(overrides.map { it.key }.distinct().size == overrides.size, "Duplicate anchor override keys")
        val original = knowledge.anchors.associateBy { it.key }
        val base = targetBase?.anchors.orEmpty().associateBy { it.key }
        val rules = (original.mapValues { it.value.rule } + base.mapValues { it.value.rule }).toMutableMap()
        overrides.forEach { change ->
            requireInput(change.key.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid anchor key")
            requireInput(change.expectedRevision == null || change.expectedRevision == (original[change.key]?.rule ?: base[change.key]?.rule)?.revisionId, "Anchor expectedRevision differs from frozen source")
            rules[change.key] = RuleProofs.revision(change.locators, change.strategy)
        }
        rules.values.forEach(StrategyRegistry::validate)
        rules.toSortedMap()
    }

    private fun validateRuleJson(item: com.google.gson.JsonObject) {
        item["locators"]?.let(RuleJson::validateLocators)
        val strategy = item["strategy"]?.takeUnless { it.isJsonNull }
        requireInput(item.has("locators") || strategy != null, "Rule requires locators or strategy")
        strategy?.let {
            requireInput(it.isJsonObject, "strategy must be an object")
            val obj = it.asJsonObject
            requireInput(obj.keySet().all { key -> key in setOf("strategyId", "parameters", "resultKind", "requires") }, "Unknown strategy property")
            for (key in listOf("strategyId", "resultKind")) obj[key]?.let { value -> requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isString, "Strategy $key must be a string") }
            requireInput(obj["strategyId"] != null, "Missing strategyId")
            obj["parameters"]?.let { value -> requireInput(value.isJsonObject, "Strategy parameters must be an object") }
            obj["requires"]?.let { value ->
                requireInput(value.isJsonObject && value.asJsonObject.entrySet().all { e -> e.value.isJsonPrimitive && e.value.asJsonPrimitive.isString }, "Strategy requires must map role names to anchor keys")
            }
        }
    }

    internal fun validateTargetBase(source: VersionKnowledge, target: Artifact, base: VersionKnowledge?) {
        if (base == null) return
        requireInput(base.artifact.sha256 == target.sha256 && base.migrationSourceKnowledgeId == source.knowledgeId, "Target base belongs to another APK or source knowledge")
        val originals = source.entries.associateBy { it.semanticId }
        requireInput(base.entries.all { originals[it.semanticId]?.name == it.name }, "Target base adds or renames a frozen migration target")
        requireInput(base.unresolved.map { it.entry.semanticId }.toSet() == (originals.keys - base.entries.map { it.semanticId }.toSet()) + source.unresolved.map { it.entry.semanticId }.toSet(), "Target base lost unresolved source knowledge")
        requireInput(base.knowledgeId == KnowledgeFiles.id(base), "Target base identity mismatch")
    }

    private fun validateDependencyDefinitions(targets: List<RuleRevision>, definitions: Map<String, RuleRevision>) {
        RuleProofs.validateDependencies(definitions, targets, emptyList())
        (targets + definitions.values).forEach { rule ->
            StrategyRegistry.validateDependencyDefinitions(rule, definitions)
        }
    }

    internal fun reusable(proof: Resolution, rule: RuleRevision, anchors: Map<String, SupportAnchor>, buildId: String): Boolean =
        proof.status == ResolutionStatus.UNIQUE && proof.rule == rule && proof.engineBuildId == buildId &&
            rule.requires.values.all { it in anchors } && proof.dependencies == rule.requires.mapValues { (_, key) -> anchors.getValue(key) }

    internal fun stableAnchors(input: Map<String, SupportAnchor>): Map<String, SupportAnchor> {
        var current = input
        while (true) {
            val next = current.filter { (_, anchor) -> anchor.rule.requires.values.all { it in current } &&
                anchor.resolution.dependencies == anchor.rule.requires.mapValues { (_, key) -> current.getValue(key) } }
            if (next.size == current.size) return next
            current = next
        }
    }

    private fun proofRefs(proof: Resolution, inventory: Map<String, String>): Set<ClassRef> = buildSet {
        proof.candidates.forEach { add(it.ref); addAll(it.matches.flatMap { m -> m.relatedRefs + m.trace.map { it.owner } }) }
        addAll(KnowledgeFiles.evidenceClosure(proof).map { it.ref })
        proof.dependencies.values.forEach { add(it.binding.owner) }
        proof.matches.mapNotNull { it.field?.call?.declaringType }.forEach { raw -> inventory[raw]?.let { add(ClassRef(proof.apkSha256, raw, it)) } }
    }

    private fun ensureTargetEvidence(dir: Path, run: MigrationRun, refs: Set<ClassRef>) {
        val available = EvidenceFiles.available(dir, run.runId).map { it.ref }.toSet()
        val missing = refs - available
        if (missing.isEmpty()) return
        requireInput(missing.all { it.apkSha256 == run.targetApk.sha256 && run.targetInventory[it.descriptor] == it.dexEntry }, "Anchor evidence is outside target APK")
        val code = ApkReader.decompile(Path.of(run.targetApk.path), missing.map { it.descriptor }.toSet(), dir.resolve("work/anchor-evidence"))
        EvidenceFiles.publish(dir, run.runId, run.targetApk, missing.toList(), code)
    }

    private fun copyDependencies(proof: Resolution, baseRoot: Path?, out: Path) {
        val evidence = KnowledgeFiles.evidenceClosure(proof)
        if (evidence.isEmpty()) return
        requireInput(baseRoot != null, "Dependency proof has no target base package")
        evidence.forEach { KnowledgeFiles.copyEvidence(baseRoot!!, out, it) }
    }

    private fun copyEntry(entry: KnowledgeEntry, sourceRoot: Path, out: Path) = KnowledgeFiles.copyEntry(sourceRoot, out, entry)
    private fun requireScan(scan: ScanResult) { if (scan.stats.diagnostics.isNotEmpty()) throw ExecutionException("DEX scan incomplete: ${scan.stats.diagnostics.joinToString("; ")}") }
}
