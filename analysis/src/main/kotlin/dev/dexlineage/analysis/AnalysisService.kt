package dev.dexlineage.analysis

import com.google.gson.JsonParser
import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.rules.RuleEngine
import dev.dexlineage.rules.RuleJson
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant

object AnalysisService {
    fun discover(apkPath: Path, profilePath: Path, outDir: Path): AnalysisDiscoveryResult {
        val apk = Digests.artifact(apkPath)
        val profileSource = Digests.artifact(profilePath)
        val profile = readProfile(profilePath)
        createNewDirectory(outDir)
        try {
            val query = RuleEngine.query(apk, listOf(profile.discovery), outDir.resolve("work"))
            complete(query.scan)
            val leads = createLeads(apk, profile, query.matches)
            var discovery = AnalysisDiscovery(discoveryId = "", engineBuildId = ResolutionEngine.buildId(), apk = apk, profileSource = profileSource, profile = profile,
                classInventory = query.scan.classes.toSortedMap(), leads = leads, matches = query.matches, scan = query.scan.stats,
                matchCounts = MatchStatus.entries.associate { state -> state.name to query.matches.count { it.status == state } },
                conditionCounts = MatchStatus.entries.associate { state -> state.name to query.matches.sumOf { match -> match.factors.count { it.status == state } } },
                analysisDiagnostics = query.analysis?.diagnostics.orEmpty().sorted(), analysisMillis = query.analysis?.elapsedMillis ?: 0,
                createdAt = Instant.now().toString())
            discovery = discovery.copy(discoveryId = discovery.fingerprint())
            val code = query.analysis?.code.orEmpty().distinctBy { it.descriptor }
            val evidence = if (code.isEmpty()) emptyList() else EvidenceFiles.publish(outDir, discovery.discoveryId, apk,
                code.map { ClassRef(apk.sha256, it.descriptor, discovery.classInventory.getValue(it.descriptor)) }, code)
            listOf(apk, profileSource).forEach(Digests::verify)
            val discoveryPath = outDir.resolve("discovery.json")
            JsonFiles.writeNew(discoveryPath, discovery)
            val items = profile.locatorTemplate?.let { template -> leads.filter { lead -> lead.matches.any { it.status == MatchStatus.PASS } }
                .map { lead -> AnalysisRuleItem(key = lead.key, proposedName = lead.suggestedName,
                    locators = listOf(RuleEngine.instantiate(template, lead.captures)), discoveryKey = lead.key) } }.orEmpty()
            val rulesPath = if (items.isEmpty()) null else outDir.resolve("rules.json").also {
                JsonFiles.writeNew(it, AnalysisRuleFile(discovery = Digests.artifact(discoveryPath), minConfidence = profile.minConfidence, items = items))
            }
            return AnalysisDiscoveryResult(discoveryId = discovery.discoveryId, leads = leads.size, draftedRules = items.size,
                discoveryPath = discoveryPath.toAbsolutePath().toString(), rulesPath = rulesPath?.toAbsolutePath()?.toString(),
                evidence = evidence, scan = discovery.scan, analysisMillis = discovery.analysisMillis)
        } catch (e: Exception) { failure(outDir, "analysis.discover", e); throw e }
    }

    fun readProfile(path: Path): AnalysisProfile = checkedInput("Analysis discovery profile") {
        val json = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(json.keySet().all { it in setOf("schemaVersion", "id", "discovery", "nameCapture", "locatorTemplate", "minConfidence") }, "Unknown discovery profile field")
        RuleJson.validateLocator(json.get("discovery"))
        json.get("locatorTemplate")?.takeUnless { it.isJsonNull }?.let { RuleJson.validateLocator(it, template = true) }
        val profile = JsonFiles.read(path, AnalysisProfile::class.java)
        requireInput(profile.id.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,79}")), "Invalid profile ID")
        val level: Confidence? = profile.minConfidence
        requireInput(level != null, "Invalid confidence threshold")
        RuleEngine.validate(profile.discovery)
        val captures = profile.discovery.captures.map { it.name }.toSet() + if (profile.discovery.kind == "string-use") setOf("literal") else emptySet()
        profile.nameCapture?.let { requireInput(it in captures, "nameCapture must refer to a discovery capture") }
        profile.locatorTemplate?.let { template ->
            RuleEngine.validate(template)
            requireInput(template.anchorFromCapture in captures, "Locator anchor capture is not produced by discovery")
            requireInput(template.factors.mapNotNull { it.valueFromCapture }.all { it in captures }, "Locator factor capture is not produced by discovery")
        }
        profile
    }

    internal fun createLeads(apk: Artifact, profile: AnalysisProfile, matches: List<MatchFact>): List<DiscoveryLead> =
        matches.filter { it.status != MatchStatus.FAIL }.groupBy { it.owner }.entries.sortedBy { it.key.descriptor }.flatMap { (owner, ownerFacts) ->
            val passing = ownerFacts.filter { it.status == MatchStatus.PASS }
            val groups = if (passing.isEmpty()) listOf(emptyMap<String, String>() to ownerFacts) else passing.groupBy { it.captures.toSortedMap() }.toList()
            groups.map { (captures, facts) -> DiscoveryLead(
                Digests.text("analysis-lead\n${apk.sha256}\n${owner.descriptor}\n${JsonFiles.encode(captures)}"), owner,
                profile.nameCapture?.let(captures::get), captures, facts) }
        }.sortedBy { it.key }

    fun readRules(path: Path): AnalysisRuleFile = checkedInput("Analysis rules") {
        val json = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(json.keySet().all { it in setOf("schemaVersion", "kind", "discovery", "minConfidence", "items") }, "Unknown Analysis rule-file field")
        json.getAsJsonArray("items")?.forEach { element ->
            requireInput(element.asJsonObject.keySet().all { it in setOf("key", "semanticId", "proposedName", "locators", "discoveryKey") }, "Analysis rules cannot specify expected target identities or unknown fields")
            RuleJson.validateLocators(element.asJsonObject.get("locators"))
        }
        val rules = JsonFiles.read(path, AnalysisRuleFile::class.java)
        validateRules(rules)
        rules
    }

    private fun validateRules(rules: AnalysisRuleFile) = checkedInput("Analysis rule definitions") {
        requireInput(rules.kind == "analysis-rules", "Expected analysis-rules document")
        val level: Confidence? = rules.minConfidence
        requireInput(level != null, "Invalid confidence threshold")
        requireInput(rules.items.isNotEmpty() && rules.items.map { it.key }.distinct().size == rules.items.size, "Empty or duplicate Analysis task keys")
        rules.items.forEach { item ->
            requireInput(item.key.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid Analysis task key")
            requireInput(item.semanticId == null || item.semanticId.isNotBlank(), "Empty semanticId")
            requireInput(item.locators.isNotEmpty(), "Target needs at least one locator")
            item.locators.forEach(RuleEngine::validate)
            requireInput(item.discoveryKey == null || rules.discovery != null, "discoveryKey requires a discovery artifact")
        }
    }

    fun prepare(apkPath: Path, rulesPath: Path, runDir: Path, baseKnowledgePath: Path? = null): AnalysisRun {
        val apk = Digests.artifact(apkPath)
        val rulesFile = Digests.artifact(rulesPath)
        val rules = readRules(rulesPath)
        val discoveryFile = rules.discovery?.let { supplied ->
            val resolved = rulesPath.toAbsolutePath().parent.resolve(supplied.path).normalize()
            supplied.copy(path = resolved.toString()).also(Digests::verify)
        }
        val discovery = discoveryFile?.let { readDiscovery(Path.of(it.path), apk) }
        val baseFile = baseKnowledgePath?.let(Digests::artifact)
        val base = baseKnowledgePath?.let(KnowledgeFiles::read)
        requireInput(base == null || base.artifact.sha256 == apk.sha256, "Analysis base belongs to another APK")
        val semanticInputs = rules.items.mapNotNull { it.semanticId }
        requireInput(semanticInputs.distinct().size == semanticInputs.size, "Duplicate semanticId updates")
        rules.items.forEach { item ->
            item.semanticId?.let { id -> requireInput(findExistingById(base, id)?.binding?.apkSha256 == apk.sha256, "Unknown or cross-APK semanticId: $id") }
            item.discoveryKey?.let { key -> requireInput(discovery?.leads?.any { it.key == key } == true, "Unknown discovery lead: $key") }
        }
        createNewDirectory(runDir)
        try {
            val revisions = rules.items.map { RuleProofs.revision(it.locators) }
            val batch = ResolutionEngine.execute(apk, revisions, runDir.resolve("work"))
            complete(batch.scan)
            base?.entries?.forEach { entry -> requireInput(batch.scan.classes[entry.binding.descriptor] == entry.binding.dexEntry, "Base class is absent from current APK") }
            val tasks = rules.items.mapIndexed { index, item ->
                makeTask(apk, item, revisions[index], batch.resolutions.getValue(revisions[index].revisionId), discovery, base)
            }.sortedBy { it.taskId }
            var run = AnalysisRun(runId = "", engineBuildId = ResolutionEngine.buildId(), apk = apk, rulesFile = rulesFile, rules = rules,
                discoveryFile = discoveryFile, discovery = discovery, baseFile = baseFile, baseKnowledge = base,
                classInventory = batch.scan.classes.toSortedMap(), tasks = tasks, scan = batch.scan.stats,
                analysisDiagnostics = batch.analysis?.diagnostics.orEmpty(), analysisMillis = batch.analysis?.elapsedMillis ?: 0, createdAt = Instant.now().toString())
            run = run.copy(runId = run.fingerprint())
            batch.analysis?.code?.takeIf { it.isNotEmpty() }?.let { code ->
                EvidenceFiles.publish(runDir, run.runId, apk, code.map { ClassRef(apk.sha256, it.descriptor, run.classInventory.getValue(it.descriptor)) }, code)
            }
            listOfNotNull(apk, rulesFile, discoveryFile, baseFile).forEach(Digests::verify)
            JsonFiles.writeNew(runDir.resolve("run.json"), run)
            return run
        } catch (e: Exception) { failure(runDir, "analysis.prepare", e); throw e }
    }

    internal fun makeTask(apk: Artifact, item: AnalysisRuleItem, rule: RuleRevision, resolution: Resolution,
                          discovery: AnalysisDiscovery?, base: VersionKnowledge?): AnalysisTask {
        val expected = item.discoveryKey?.let { key -> discovery!!.leads.single { it.key == key }.owner }
        val unique = resolution.uniqueRef
        val explicit = item.semanticId?.let { findExistingById(base, it) }
        val inferred = if (item.semanticId == null && unique != null) base?.entries?.singleOrNull { it.binding == unique } else null
        val existing = explicit ?: inferred
        val occupied = unique?.let { target -> base?.entries?.singleOrNull { it.binding == target } }
        val unclaimedPending = if (item.semanticId == null && unique != null) base?.unresolved?.any { it.entry.binding == unique } == true else false
        val reason = when {
            resolution.status != ResolutionStatus.UNIQUE -> "resolution_${resolution.status.name.lowercase()}"
            expected != null && expected != unique -> "discovery_owner_mismatch"
            existing != null && existing.binding != unique -> "existing_binding_changed"
            existing != null && occupied != null && existing.semanticId != occupied.semanticId -> "semantic_identity_conflict"
            unclaimedPending -> "pending_requires_explicit_semantic_id"
            else -> null
        }
        val semanticId = existing?.semanticId ?: item.semanticId ?: unique?.let { Digests.text("semantic\n${apk.sha256}\n${it.descriptor}") }
        return AnalysisTask(item.key, item, rule, resolution, expected, existing, semanticId, reason)
    }

    fun readRun(dir: Path, verifyInputs: Boolean = true): AnalysisRun = checkedInput("Analysis run") {
        val run = JsonFiles.read(dir.resolve("run.json"), AnalysisRun::class.java)
        requireInput(run.kind == "analysis-run" && run.toolVersion == TOOL_VERSION && run.jadxVersion == JADX_VERSION, "Unsupported Analysis run")
        requireInput(run.runId == run.fingerprint(), "Analysis run fingerprint mismatch")
        requireInput(run.engineBuildId.isNotBlank(), "Missing Analysis engine build identity")
        requireInput(run.scan.diagnostics.isEmpty(), "Incomplete Analysis scan")
        validateRules(run.rules)
        requireInput(run.tasks.map { it.taskId }.distinct().size == run.tasks.size, "Duplicate Analysis tasks")
        requireInput(run.tasks.map { it.request }.sortedBy { it.key } == run.rules.items.sortedBy { it.key }, "Tasks differ from frozen rule input")
        requireInput((run.baseFile == null) == (run.baseKnowledge == null) && (run.discoveryFile == null) == (run.discovery == null), "Incomplete frozen Analysis inputs")
        requireInput(run.baseKnowledge == null || run.baseKnowledge.artifact.sha256 == run.apk.sha256 && run.baseKnowledge.knowledgeId == KnowledgeFiles.id(run.baseKnowledge), "Base knowledge identity mismatch")
        val semanticInputs = run.rules.items.mapNotNull { it.semanticId }
        requireInput(semanticInputs.distinct().size == semanticInputs.size, "Duplicate semanticId updates")
        run.rules.items.forEach { item ->
            item.semanticId?.let { requireInput(findExistingById(run.baseKnowledge, it)?.binding?.apkSha256 == run.apk.sha256, "Unknown or cross-APK semanticId") }
            item.discoveryKey?.let { key -> requireInput(run.discovery?.leads?.any { it.key == key } == true, "Unknown discovery lead") }
        }
        run.tasks.forEach { task ->
            RuleProofs.validate(task.rule)
            RuleProofs.validate(task.resolution)
            requireInput(task.rule == RuleProofs.revision(task.request.locators) && task.resolution.rule == task.rule && task.resolution.apkSha256 == run.apk.sha256, "Task proof differs from rule/APK")
            requireInput(task.resolution.engineBuildId == run.engineBuildId, "Task proof differs from the frozen engine build")
            requireInput(task.resolution.matches.all { run.classInventory[it.owner.descriptor] == it.owner.dexEntry }, "Resolution class/DEX identity mismatch")
            requireInput(task == makeTask(run.apk, task.request, task.rule, task.resolution, run.discovery, run.baseKnowledge), "Task target or semantic identity was altered")
        }
        if (verifyInputs) {
            listOfNotNull(run.apk, run.rulesFile, run.discoveryFile, run.baseFile).forEach(Digests::verify)
            requireInput(readRules(Path.of(run.rulesFile.path)) == run.rules, "Rules differ from frozen input")
            run.baseFile?.let { requireInput(KnowledgeFiles.read(Path.of(it.path)) == run.baseKnowledge, "Base package differs from frozen input") }
            run.discoveryFile?.let { requireInput(readDiscovery(Path.of(it.path), run.apk) == run.discovery, "Discovery differs from frozen input") }
        }
        run
    }

    fun tasks(dir: Path, state: String? = null, offset: Int = 0, limit: Int = 20): AnalysisTaskPage {
        requireInput(offset >= 0 && limit > 0, "Invalid task pagination")
        val run = readRun(dir)
        val latest = ReviewStore.latest(dir, run.runId)
        val decisions = decisions(dir, run, latest)
        val filter = (state ?: "UNREVIEWED").takeUnless { it.equals("ALL", true) }?.let { checkedInput("task state") { TaskState.valueOf(it.uppercase()) } }
        val filtered = decisions.filter { filter == null || it.state == filter }.map { d ->
            AnalysisTaskView(run.tasks.single { it.taskId == d.taskId }, d.state, d.reason, latest[d.taskId]?.revisionId)
        }
        return AnalysisTaskPage(runId = run.runId, total = filtered.size, offset = offset, limit = limit, counts = counts(decisions),
            items = filtered.drop(offset).take(limit), carriedUnresolved = run.baseKnowledge?.unresolved.orEmpty())
    }

    fun inspect(dir: Path, taskIds: Set<String>): List<EvidenceRecord> {
        val run = readRun(dir)
        requireInput(taskIds.isNotEmpty() && taskIds.all { id -> run.tasks.any { it.taskId == id } }, "Unknown or empty Analysis task selection")
        val refs = run.tasks.filter { it.taskId in taskIds }.flatMap { AnalysisPolicy.allowedRefs(run, it) }.toSet()
        val existing = EvidenceFiles.available(dir, run.runId).map { it.ref }.toSet()
        val missing = (refs - existing).toMutableSet()
        val reusable = run.baseKnowledge?.let { base -> (base.entries + base.unresolved.map { it.entry }).flatMap { it.evidence }
            .filter { it.ref in missing && it.ref.apkSha256 == run.apk.sha256 }.distinctBy { it.ref } }.orEmpty()
        if (reusable.isNotEmpty()) {
            val root = Path.of(run.baseFile!!.path).parent
            val code = reusable.map { e -> DecompiledClass(e.ref.descriptor, Files.readString(root.resolve(e.javaPath)),
                e.smaliPath?.let { Files.readString(root.resolve(it)) }, e.incomplete, e.diagnostics, 0) }
            EvidenceFiles.publish(dir, run.runId, run.apk, reusable.map { it.ref }, code)
            missing.removeAll(reusable.map { it.ref }.toSet())
        }
        if (missing.isNotEmpty()) {
            val code = ApkReader.decompile(Path.of(run.apk.path), missing.map { it.descriptor }.toSet(), dir.resolve("work/inspect"))
            EvidenceFiles.publish(dir, run.runId, run.apk, missing.toList(), code)
        }
        return refs.map { EvidenceFiles.read(dir, run.runId, Identities.evidenceId(run.runId, it)) }.sortedBy { it.evidenceId }
    }

    fun submit(dir: Path, reviewFile: Path): AnalysisSubmitResult = checkedInput("Analysis submission") {
        val run = readRun(dir)
        val json = JsonParser.parseString(Files.readString(reviewFile)).asJsonObject
        json.getAsJsonArray("items")?.forEach { item -> requireInput(item.asJsonObject.keySet().all {
            it in setOf("taskId", "resolutionId", "ruleRevisionId", "action", "name", "level", "rationale", "unverified", "evidenceIds", "supersedes")
        }, "Review cannot select an entity or contain unsupported fields") }
        val batch = JsonFiles.read(reviewFile, AnalysisReviewBatch::class.java)
        requireInput(batch.runId == run.runId && batch.apkSha256 == run.apk.sha256, "Analysis review input binding mismatch")
        requireInput(batch.items.isNotEmpty() && batch.items.map { it.taskId }.distinct().size == batch.items.size, "Empty or duplicate review batch")
        val evidence = EvidenceFiles.available(dir, run.runId).associateBy { it.evidenceId }
        batch.items.forEach { review ->
            val task = run.tasks.singleOrNull { it.taskId == review.taskId } ?: throw ValidationException("Unknown Analysis task")
            AnalysisPolicy.validateReview(run, task, review, evidence)
        }
        val stored = ReviewStore.submitBatch(dir, run.runId, batch.items.sortedBy { it.taskId }.map { ReviewRequest(it.taskId, it.supersedes, it) })
        AnalysisSubmitResult(runId = run.runId, revisions = stored.associate { it.taskId to it.revisionId }, counts = counts(decisions(dir, run)))
    }

    fun publish(dir: Path, out: Path, reviewSnapshot: Path? = null): AnalysisPublishResult {
        val run = readRun(dir)
        val latest = reviewSnapshot?.let { ReviewStore.fromSnapshot(dir, run.runId, it) } ?: ReviewStore.latest(dir, run.runId)
        val decisions = decisions(dir, run, latest)
        val accepted = decisions.filter { it.state == TaskState.ACCEPTED }
        createNewDirectory(out)
        val entries = run.baseKnowledge?.entries.orEmpty().associateBy { it.semanticId }.toMutableMap()
        val pending = run.baseKnowledge?.unresolved.orEmpty().associateBy { it.entry.semanticId }.toMutableMap()
        val updatedIds = accepted.map { it.semanticId!! }.toSet()
        run.baseFile?.let { baseFile ->
            val sourceRoot = Path.of(baseFile.path).parent
            (entries.values.filter { it.semanticId !in updatedIds } + pending.values.filter { it.entry.semanticId !in updatedIds }.map { it.entry })
                .flatMap { it.evidence }.forEach { KnowledgeFiles.copyEvidence(sourceRoot, out, it) }
        }
        accepted.forEach { decision ->
            val task = run.tasks.single { it.taskId == decision.taskId }
            val review = decision.review!!
            val evidence = review.evidenceIds.sorted().map { EvidenceFiles.export(dir, run.runId, it, out) }
            entries[decision.semanticId!!] = KnowledgeEntry(decision.semanticId, decision.name!!, decision.target!!,
                RuleProofs.captures(task.resolution), task.rule.locators, evidence, review.rationale,
                "analysis:${run.runId}:${latest.getValue(task.taskId).revisionId}", task.rule, task.resolution)
            pending.remove(decision.semanticId)
        }
        val knowledge = KnowledgeFiles.write(out, VersionKnowledge(knowledgeId = "", artifact = run.apk,
            entries = entries.values.toList(), unresolved = pending.values.toList(), provenance = "analysis:${run.runId}", parentKnowledgeId = run.baseKnowledge?.knowledgeId))
        MappingOutput.write(out.resolve("mapping.tiny"), knowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        val cached = EvidenceFiles.available(dir, run.runId)
        JsonFiles.writeNew(out.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "analysis-report", "runId" to run.runId,
            "knowledgeId" to knowledge.knowledgeId, "parentKnowledgeId" to knowledge.parentKnowledgeId, "apk" to run.apk,
            "reviewRevisions" to latest.mapValues { it.value.revisionId }, "tasks" to run.tasks, "decisions" to decisions,
            "counts" to counts(decisions), "acceptedUpdates" to accepted.size, "confirmed" to knowledge.entries.size,
            "resolutionCounts" to ResolutionStatus.entries.associateWith { status -> run.tasks.count { it.resolution.status == status } },
            "carriedConfirmed" to (knowledge.entries.size - accepted.size), "unresolved" to knowledge.unresolved.size,
            "scan" to run.scan, "analysisMillis" to run.analysisMillis, "analysisDiagnostics" to run.analysisDiagnostics,
            "evidenceMetrics" to mapOf("scope" to "emitted_or_cached_evidence", "agentReadsMeasured" to false,
                "ownerApkPairs" to cached.map { it.ref }.distinct().size, "javaLines" to cached.sumOf { e -> Files.lines(dir.resolve(e.javaPath)).use { it.count() } },
                "smaliLines" to cached.sumOf { e -> e.smaliPath?.let { path -> Files.lines(dir.resolve(path)).use { it.count() } } ?: 0L }, "incompleteClasses" to cached.count { it.incomplete })))
        return AnalysisPublishResult(runId = run.runId, knowledgeId = knowledge.knowledgeId, acceptedUpdates = accepted.size,
            confirmed = knowledge.entries.size, unresolved = knowledge.unresolved.size, counts = counts(decisions),
            knowledgePath = out.resolve("knowledge.json").toString(), mappingPath = out.resolve("mapping.tiny").toString(), reportPath = out.resolve("report.json").toString())
    }

    private fun readDiscovery(path: Path, apk: Artifact): AnalysisDiscovery = checkedInput("Analysis discovery") {
        val discovery = JsonFiles.read(path, AnalysisDiscovery::class.java)
        requireInput(discovery.kind == "analysis-discovery" && discovery.toolVersion == TOOL_VERSION && discovery.jadxVersion == JADX_VERSION, "Unsupported discovery")
        requireInput(discovery.discoveryId == discovery.fingerprint() && discovery.apk.sha256 == apk.sha256, "Discovery identity mismatch")
        requireInput(discovery.engineBuildId.isNotBlank(), "Missing discovery engine build identity")
        requireInput(discovery.scan.diagnostics.isEmpty(), "Incomplete discovery scan")
        requireInput(discovery.leads.map { it.key }.distinct().size == discovery.leads.size, "Duplicate discovery leads")
        discovery.leads.forEach { requireInput(it.owner.apkSha256 == apk.sha256 && discovery.classInventory[it.owner.descriptor] == it.owner.dexEntry, "Discovery owner identity mismatch") }
        requireInput(discovery.matches.all { it.owner.apkSha256 == apk.sha256 && discovery.classInventory[it.owner.descriptor] == it.owner.dexEntry && it.locatorIndex == 0 }, "Discovery facts have a different owner or locator")
        requireInput(discovery.leads == createLeads(apk, discovery.profile, discovery.matches), "Discovery leads differ from frozen facts")
        discovery
    }
    private fun findExistingById(base: VersionKnowledge?, id: String): KnowledgeEntry? = base?.entries?.singleOrNull { it.semanticId == id }
        ?: base?.unresolved?.singleOrNull { it.entry.semanticId == id }?.entry
    private fun complete(scan: ScanResult) { if (scan.stats.diagnostics.isNotEmpty()) throw ExecutionException("DEX scan incomplete: ${scan.stats.diagnostics.joinToString("; ")}") }
    private fun failure(dir: Path, operation: String, e: Exception) {
        if (!Files.exists(dir.resolve("failure.json"))) JsonFiles.writeNew(dir.resolve("failure.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "operation" to operation, "message" to (e.message ?: e.javaClass.name)))
    }
    private fun decisions(dir: Path, run: AnalysisRun, latest: Map<String, StoredReview> = ReviewStore.latest(dir, run.runId)): List<AnalysisDecision> = checkedInput("Analysis review history") {
        val reviews = latest.mapValues { (_, stored) -> JsonFiles.gson.fromJson(stored.payload, AnalysisReview::class.java) }
        AnalysisPolicy.decide(run, reviews, EvidenceFiles.available(dir, run.runId).associateBy { it.evidenceId })
    }
    private fun counts(decisions: List<AnalysisDecision>): Map<String, Int> = TaskState.entries.associate { state -> state.name to decisions.count { it.state == state } }
}
