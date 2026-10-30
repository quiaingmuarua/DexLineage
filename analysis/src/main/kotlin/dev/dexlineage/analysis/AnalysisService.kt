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
import dev.dexlineage.rules.StrategyRegistry
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant

object AnalysisService {
    fun importJadx(apkPath: Path, projectPath: Path, outDir: Path): ManualCorpus = ManualCorpusFiles.importJadx(apkPath, projectPath, outDir)

    fun discover(apkPath: Path, profilePath: Path, outDir: Path, baseKnowledgePath: Path? = null): AnalysisDiscoveryResult {
        val apk = Digests.artifact(apkPath)
        val profileSource = Digests.artifact(profilePath)
        val profile = readProfile(profilePath)
        val baseFile = baseKnowledgePath?.let(Digests::artifact)
        val base = baseKnowledgePath?.let(KnowledgeFiles::read)
        requireInput(base == null || base.artifact.sha256 == apk.sha256, "Discovery base belongs to another APK")
        createNewDirectory(outDir)
        try {
            val rule = RuleProofs.revision(if (profile.strategy == null) listOf(profile.discovery) else emptyList(), profile.strategy)
            val available = usableAnchors(base, base?.anchors.orEmpty().associate { it.key to it.rule }, ResolutionEngine.buildId())
            requireInput(rule.requires.values.all { it in available }, "Discovery dependencies are not resolved in its base knowledge")
            val query = StrategyRegistry.discover(apk, rule, outDir.resolve("work"), available)
            complete(query.scan)
            val leads = createLeads(apk, profile, query.matches)
            var discovery = AnalysisDiscovery(discoveryId = "", engineBuildId = ResolutionEngine.buildId(), apk = apk, profileSource = profileSource, profile = profile,
                classInventory = query.scan.classes.toSortedMap(), leads = leads, matches = query.matches, scan = query.scan.stats,
                matchCounts = MatchStatus.entries.associate { state -> state.name to query.matches.count { it.status == state } },
                conditionCounts = MatchStatus.entries.associate { state -> state.name to query.matches.sumOf { match -> match.factors.count { it.status == state } } },
                analysisDiagnostics = query.analysis?.diagnostics.orEmpty().sorted(), analysisMillis = query.analysis?.elapsedMillis ?: 0,
                createdAt = Instant.now().toString(), baseFile = baseFile, baseKnowledge = base,
                rpcCalls = query.rpcCalls, unresolvedPaths = query.unresolvedPaths)
            discovery = discovery.copy(discoveryId = discovery.fingerprint())
            val code = query.analysis?.code.orEmpty().distinctBy { it.descriptor }
            val evidence = if (code.isEmpty()) emptyList() else EvidenceFiles.publish(outDir, discovery.discoveryId, apk,
                code.map { ClassRef(apk.sha256, it.descriptor, discovery.classInventory.getValue(it.descriptor)) }, code)
            listOfNotNull(apk, profileSource, baseFile).forEach(Digests::verify)
            val discoveryPath = outDir.resolve("discovery.json")
            JsonFiles.writeNew(discoveryPath, discovery)
            val catalogPath = discovery.rpcCalls?.let { outDir.resolve("rpc-catalog.json").also { path ->
                JsonFiles.writeNew(path, RpcAnalysis.catalog(discovery))
            } }
            val items = if (profile.rpcDrafts != null) RpcAnalysis.drafts(profile, leads) else leads.filter { lead -> lead.matches.any { it.status == MatchStatus.PASS } }.mapNotNull { lead ->
                profile.locatorTemplate?.let { template -> AnalysisRuleItem(key = lead.key, proposedName = lead.suggestedName,
                    locators = listOf(RuleEngine.instantiate(template, lead.captures)), discoveryKey = lead.key) }
                    ?: profile.strategyTemplate?.let { template ->
                        val params = template.parameters.deepCopy()
                        profile.parameterCaptures.forEach { (parameter, capture) ->
                            params.addProperty(parameter, lead.captures[capture] ?: throw ValidationException("Missing discovery capture $capture"))
                        }
                        AnalysisRuleItem(key = lead.key, proposedName = lead.suggestedName,
                            discoveryKey = lead.key, strategy = template.copy(parameters = params))
                    }
            }
            val rulesPath = if (items.isEmpty()) null else outDir.resolve("rules.json").also {
                JsonFiles.writeNew(it, AnalysisRuleFile(discovery = Digests.artifact(discoveryPath), minConfidence = profile.minConfidence, items = items))
            }
            return AnalysisDiscoveryResult(discoveryId = discovery.discoveryId, leads = leads.size, draftedRules = items.size,
                discoveryPath = discoveryPath.toAbsolutePath().toString(), rulesPath = rulesPath?.toAbsolutePath()?.toString(),
                evidence = evidence, scan = discovery.scan, analysisMillis = discovery.analysisMillis, catalogPath = catalogPath?.toAbsolutePath()?.toString())
        } catch (e: Exception) { failure(outDir, "analysis.discover", e); throw e }
    }

    fun readProfile(path: Path): AnalysisProfile = checkedInput("Analysis discovery profile") {
        val json = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(json.keySet().all { it in setOf("schemaVersion", "id", "discovery", "nameCapture", "locatorTemplate", "minConfidence", "strategy", "strategyTemplate", "parameterCaptures", "rpcDrafts") }, "Unknown discovery profile field")
        if (json.get("strategy")?.isJsonNull != false) RuleJson.validateLocator(json.get("discovery"))
        else validateStrategyJson(json.get("strategy").asJsonObject)
        json.get("strategyTemplate")?.takeUnless { it.isJsonNull }?.asJsonObject?.let(::validateStrategyJson)
        json.get("locatorTemplate")?.takeUnless { it.isJsonNull }?.let { RuleJson.validateLocator(it, template = true) }
        json.get("rpcDrafts")?.takeUnless { it.isJsonNull }?.asJsonObject?.let {
            requireInput(it.keySet().all { key -> key in setOf("reviewServices", "requestSuffix", "responseSuffix") }, "Unknown RPC drafting option")
        }
        val profile = JsonFiles.read(path, AnalysisProfile::class.java)
        requireInput(profile.id.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,79}")), "Invalid profile ID")
        val level: Confidence? = profile.minConfidence
        requireInput(level != null, "Invalid confidence threshold")
        if (profile.strategy == null) RuleEngine.validate(profile.discovery)
        else {
            requireInput(profile.discovery.kind.isBlank(), "Discovery cannot specify both locator and strategy")
            StrategyRegistry.validate(RuleProofs.revision(emptyList(), profile.strategy))
        }
        val captures = profile.discovery.captures.map { it.name }.toSet() + if (profile.discovery.kind == "string-use") setOf("literal") else emptySet()
        profile.nameCapture?.let { requireInput(profile.strategy != null || it in captures, "nameCapture must refer to a discovery capture") }
        requireInput(profile.locatorTemplate == null || profile.strategyTemplate == null, "Use one discovery rule template")
        requireInput(profile.parameterCaptures.isEmpty() || profile.strategyTemplate != null, "parameterCaptures requires strategyTemplate")
        profile.strategyTemplate?.let { template ->
            val parameters = template.parameters.deepCopy()
            profile.parameterCaptures.forEach { (parameter, capture) ->
                requireInput(parameter.isNotBlank() && capture.isNotBlank(), "Empty discovery parameter/capture key")
                parameters.addProperty(parameter, "capture-value")
            }
            StrategyRegistry.validate(RuleProofs.revision(emptyList(), template.copy(parameters = parameters)))
        }
        profile.locatorTemplate?.let { template ->
            RuleEngine.validate(template)
            requireInput(profile.strategy != null || template.anchorFromCapture in captures, "Locator anchor capture is not produced by discovery")
            requireInput(profile.strategy != null || template.factors.mapNotNull { it.valueFromCapture }.all { it in captures }, "Locator factor capture is not produced by discovery")
        }
        RpcAnalysis.validate(profile)
        profile
    }

    internal fun createLeads(apk: Artifact, profile: AnalysisProfile, matches: List<MatchFact>): List<DiscoveryLead> =
        if (profile.strategy?.strategyId == "grpc-java.rpc-discovery") RpcAnalysis.leads(apk, profile, matches)
        else matches.filter { it.status != MatchStatus.FAIL }.groupBy { it.owner }.entries.sortedBy { it.key.descriptor }.flatMap { (owner, ownerFacts) ->
            val passing = ownerFacts.filter { it.status == MatchStatus.PASS }
            val groups = if (passing.isEmpty()) listOf(emptyMap<String, String>() to ownerFacts) else passing.groupBy { it.captures.toSortedMap() }.toList()
            groups.map { (captures, facts) -> DiscoveryLead(
                Digests.text("analysis-lead\n${apk.sha256}\n${owner.descriptor}\n${JsonFiles.encode(captures)}"), owner,
                profile.nameCapture?.let(captures::get), captures, facts) }
        }.sortedBy { it.key }

    fun readRules(path: Path): AnalysisRuleFile = checkedInput("Analysis rules") {
        val json = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(json.keySet().all { it in setOf("schemaVersion", "kind", "discovery", "minConfidence", "items", "anchors") }, "Unknown Analysis rule-file field")
        json.getAsJsonArray("items")?.forEach { element ->
            requireInput(element.asJsonObject.keySet().all { it in setOf("key", "semanticId", "proposedName", "locators", "discoveryKey", "strategy", "corpusTargetId") }, "Analysis rules cannot specify expected target identities or unknown fields")
            validateRuleJson(element.asJsonObject)
        }
        json.getAsJsonArray("anchors")?.forEach { element ->
            requireInput(element.asJsonObject.keySet().all { it in setOf("key", "locators", "strategy") }, "Unknown anchor definition field")
            validateRuleJson(element.asJsonObject)
        }
        val rules = JsonFiles.read(path, AnalysisRuleFile::class.java)
        validateRules(rules)
        rules
    }

    private fun validateRules(rules: AnalysisRuleFile) = checkedInput("Analysis rule definitions") {
        requireInput(rules.kind == "analysis-rules", "Expected analysis-rules document")
        val level: Confidence? = rules.minConfidence
        requireInput(level != null, "Invalid confidence threshold")
        requireInput(rules.items.isNotEmpty() || rules.anchors.isNotEmpty(), "Analysis rules contain no targets or anchors")
        requireInput(rules.items.map { it.key }.distinct().size == rules.items.size, "Duplicate Analysis task keys")
        requireInput(rules.anchors.map { it.key }.distinct().size == rules.anchors.size, "Duplicate anchor keys")
        requireInput(rules.items.mapNotNull { it.corpusTargetId }.distinct().size == rules.items.count { it.corpusTargetId != null }, "Duplicate corpus targets")
        rules.items.forEach { item ->
            requireInput(item.key.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid Analysis task key")
            requireInput(item.semanticId == null || item.semanticId.isNotBlank(), "Empty semanticId")
            val rule = RuleProofs.revision(item.locators, item.strategy)
            requireInput(rule.resultKind == EntityKind.CLASS, "Rename targets require CLASS results")
            StrategyRegistry.validate(rule)
            requireInput(item.discoveryKey == null || rules.discovery != null, "discoveryKey requires a discovery artifact")
        }
        rules.anchors.forEach { anchor ->
            requireInput(anchor.key.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid anchor key")
            StrategyRegistry.validate(RuleProofs.revision(anchor.locators, anchor.strategy))
        }
    }

    private fun validateRuleJson(value: com.google.gson.JsonObject) {
        value.get("strategy")?.takeUnless { it.isJsonNull }?.asJsonObject?.let(::validateStrategyJson)
        value.get("locators")?.takeUnless { it.isJsonNull }?.let { RuleJson.validateLocators(it) }
    }
    private fun validateStrategyJson(value: com.google.gson.JsonObject) {
        requireInput(value.keySet().all { it in setOf("strategyId", "parameters", "resultKind", "requires") }, "Unknown strategy field")
    }

    fun prepare(apkPath: Path, rulesPath: Path, runDir: Path, baseKnowledgePath: Path? = null, corpusPath: Path? = null,
                referenceKnowledgePaths: List<Path> = emptyList()): AnalysisRun {
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
        val references = IdentityReferences.load(referenceKnowledgePaths, apk, base)
        val corpusFile = corpusPath?.let(Digests::artifact)
        val corpus = corpusPath?.let(ManualCorpusFiles::read)
        requireInput(corpus == null || corpus.apk.sha256 == apk.sha256, "Manual corpus belongs to another APK")
        val semanticInputs = rules.items.mapNotNull { it.semanticId }
        requireInput(semanticInputs.distinct().size == semanticInputs.size, "Duplicate semanticId updates")
        rules.items.forEach { item ->
            item.semanticId?.let { id -> requireInput((findExistingById(base, id) ?: IdentityReferences.byId(references, id))?.binding?.apkSha256 == apk.sha256, "Unknown or cross-APK semanticId: $id") }
            item.discoveryKey?.let { key -> requireInput(discovery?.leads?.any { it.key == key } == true, "Unknown discovery lead: $key") }
            item.corpusTargetId?.let { key -> requireInput(corpus?.targets?.any { it.targetId == key } == true, "Unknown corpus target: $key") }
        }
        val buildId = ResolutionEngine.buildId()
        val anchorRules = anchorRules(rules, base)
        val revisions = rules.items.associate { it.key to RuleProofs.revision(it.locators, it.strategy) }
        validateDependencies(anchorRules, revisions.values.toList(), base?.anchors.orEmpty())
        val available = usableAnchors(base, anchorRules, buildId)
        val inherited = rules.items.mapNotNull { item -> inheritedEntry(item, revisions.getValue(item.key), discovery, corpus, base, available, buildId)?.let { item.key to it } }.toMap()
        createNewDirectory(runDir)
        try {
            val executing = revisions.filterKeys { it !in inherited }.values + anchorRules.filterKeys { it !in available }.values
            val batch = ResolutionEngine.execute(apk, executing.toList(), runDir.resolve("work"), available)
            complete(batch.scan)
            base?.entries?.forEach { entry -> requireInput(batch.scan.classes[entry.binding.descriptor] == entry.binding.dexEntry, "Base class is absent from current APK") }
            available.values.forEach { anchor -> requireInput(batch.scan.classes[anchor.binding.owner.descriptor] == anchor.binding.owner.dexEntry, "Base anchor class is absent from current APK") }
            val tasks = rules.items.map { item ->
                val rule = revisions.getValue(item.key)
                val inheritedProof = inherited[item.key]?.resolution
                makeTask(apk, item, rule, inheritedProof ?: batch.resolutions[rule.revisionId], discovery, base, corpus,
                    batch.waiting[rule.revisionId].orEmpty(), inheritedProof != null, references)
            }.sortedBy { it.taskId }
            val anchorTasks = anchorRules.map { (key, rule) ->
                val proof = available[key]?.resolution ?: batch.resolutions[rule.revisionId]
                AnalysisAnchorTask(key, rule, proof, if (key in available) AnalysisExecutionState.INHERITED else if (proof == null) AnalysisExecutionState.WAITING_DEPENDENCY else AnalysisExecutionState.EXECUTED,
                    if (proof == null) batch.waiting[rule.revisionId].orEmpty() else emptyList())
            }
            var run = AnalysisRun(runId = "", engineBuildId = buildId, apk = apk, rulesFile = rulesFile, rules = rules,
                discoveryFile = discoveryFile, discovery = discovery, baseFile = baseFile, baseKnowledge = base,
                classInventory = batch.scan.classes.toSortedMap(), tasks = tasks, scan = batch.scan.stats,
                analysisDiagnostics = batch.analysis?.diagnostics.orEmpty(), analysisMillis = batch.analysis?.elapsedMillis ?: 0, createdAt = Instant.now().toString(),
                anchorTasks = anchorTasks, corpusFile = corpusFile, corpus = corpus, identityReferences = references, rpcCalls = batch.rpcCalls)
            run = run.copy(runId = run.fingerprint())
            batch.analysis?.code?.takeIf { it.isNotEmpty() }?.let { code ->
                EvidenceFiles.publish(runDir, run.runId, apk, code.map { ClassRef(apk.sha256, it.descriptor, run.classInventory.getValue(it.descriptor)) }, code)
            }
            val anchorRefs = anchorTasks.mapNotNull { it.resolution }.filter { it.status == ResolutionStatus.UNIQUE }.flatMap { anchorRefs(run, it) }.toSet()
            ensureEvidence(runDir, run, anchorRefs)
            listOfNotNull(apk, rulesFile, discoveryFile, baseFile, corpusFile).forEach(Digests::verify)
            IdentityReferences.verifyFiles(references)
            JsonFiles.writeNew(runDir.resolve("run.json"), run)
            return run
        } catch (e: Exception) { failure(runDir, "analysis.prepare", e); throw e }
    }

    internal fun makeTask(apk: Artifact, item: AnalysisRuleItem, rule: RuleRevision, resolution: Resolution?,
                          discovery: AnalysisDiscovery?, base: VersionKnowledge?, corpus: ManualCorpus? = null,
                          waitingFor: List<String> = emptyList(), inherited: Boolean = false,
                          references: List<IdentityReference>? = null): AnalysisTask {
        val corpusOwner = item.corpusTargetId?.let { id -> corpus!!.targets.single { it.targetId == id }.source }
        val discoveryOwner = item.discoveryKey?.let { key -> discovery!!.leads.single { it.key == key }.owner }
        requireInput(corpusOwner == null || discoveryOwner == null || corpusOwner == discoveryOwner, "Discovery and manual source identities disagree")
        val expected = corpusOwner ?: discoveryOwner
        val unique = resolution?.uniqueRef
        val explicit = item.semanticId?.let { findExistingById(base, it) }
        val inferred = if (item.semanticId == null) base?.entries?.singleOrNull { it.binding == (unique ?: expected) } else null
        // Identity references never select candidates. Lookup happens only after a unique full-APK result.
        val reference = unique?.let { IdentityReferences.byBinding(references, it) }
        val requestedReference = if (unique != null && item.semanticId != null && explicit == null) IdentityReferences.byId(references, item.semanticId) else null
        val existing = explicit ?: inferred ?: requestedReference ?: reference?.first
        val identitySource = if (existing != null && explicit == null && inferred == null) {
            references.orEmpty().firstOrNull { source -> source.knowledge.entries.any { it.semanticId == existing.semanticId } }?.knowledge?.knowledgeId
        } else null
        val occupied = unique?.let { target -> base?.entries?.singleOrNull { it.binding == target } }
        val unclaimedPending = if (item.semanticId == null && unique != null) base?.unresolved?.any { it.entry.binding == unique } == true else false
        val reason = when {
            resolution == null -> null
            resolution.status != ResolutionStatus.UNIQUE -> "resolution_${resolution.status.name.lowercase()}"
            expected != null && expected != unique -> if (corpusOwner != null) "manual_owner_mismatch" else "discovery_owner_mismatch"
            existing != null && existing.binding != unique -> "existing_binding_changed"
            existing != null && occupied != null && existing.semanticId != occupied.semanticId -> "semantic_identity_conflict"
            unclaimedPending -> "pending_requires_explicit_semantic_id"
            else -> null
        }
        val semanticId = existing?.semanticId ?: item.semanticId ?: unique?.let { Digests.text("semantic\n${apk.sha256}\n${it.descriptor}") }
        return AnalysisTask(item.key, item, rule, resolution, expected, existing, semanticId, reason,
            if (inherited) AnalysisExecutionState.INHERITED else if (resolution == null) AnalysisExecutionState.WAITING_DEPENDENCY else AnalysisExecutionState.EXECUTED,
            waitingFor.sorted(), identitySource)
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
        requireInput((run.corpusFile == null) == (run.corpus == null), "Incomplete frozen corpus input")
        run.corpus?.let { ManualCorpusFiles.validate(it); requireInput(it.apk.sha256 == run.apk.sha256, "Corpus belongs to another APK") }
        requireInput(run.baseKnowledge == null || run.baseKnowledge.artifact.sha256 == run.apk.sha256 && run.baseKnowledge.knowledgeId == KnowledgeFiles.id(run.baseKnowledge), "Base knowledge identity mismatch")
        IdentityReferences.validate(run.identityReferences, run.apk, run.baseKnowledge)
        validateRpcCalls(run.rpcCalls, run.apk, run.classInventory)
        val semanticInputs = run.rules.items.mapNotNull { it.semanticId }
        requireInput(semanticInputs.distinct().size == semanticInputs.size, "Duplicate semanticId updates")
        run.rules.items.forEach { item ->
            item.semanticId?.let { requireInput((findExistingById(run.baseKnowledge, it) ?: IdentityReferences.byId(run.identityReferences, it))?.binding?.apkSha256 == run.apk.sha256, "Unknown or cross-APK semanticId") }
            item.discoveryKey?.let { key -> requireInput(run.discovery?.leads?.any { it.key == key } == true, "Unknown discovery lead") }
            item.corpusTargetId?.let { key -> requireInput(run.corpus?.targets?.any { it.targetId == key } == true, "Unknown corpus target") }
        }
        val catalog = anchorRules(run.rules, run.baseKnowledge)
        val available = usableAnchors(run.baseKnowledge, catalog, run.engineBuildId)
        validateDependencies(catalog, run.tasks.map { it.rule }, run.baseKnowledge?.anchors.orEmpty())
        requireInput(run.anchorTasks.map { it.key }.toSet() == catalog.keys && run.anchorTasks.size == catalog.size, "Anchor task set differs from definitions")
        run.anchorTasks.forEach { task ->
            requireInput(task.rule == catalog.getValue(task.key), "Anchor rule differs from definition")
            val inherited = available[task.key]
            val missing = task.rule.requires.values.filter { it !in available }.distinct().sorted()
            if (inherited != null) requireInput(task.executionState == AnalysisExecutionState.INHERITED && task.resolution == inherited.resolution && task.waitingFor.isEmpty(), "Inherited anchor differs from base proof")
            else if (missing.isNotEmpty()) requireInput(task.executionState == AnalysisExecutionState.WAITING_DEPENDENCY && task.resolution == null && task.waitingFor == missing, "Invalid waiting anchor")
            else {
                requireInput(task.executionState == AnalysisExecutionState.EXECUTED && task.resolution != null && task.waitingFor.isEmpty(), "Ready anchor was not executed")
                validateResolution(run, task.rule, task.resolution!!, available)
            }
        }
        run.tasks.forEach { task ->
            RuleProofs.validate(task.rule)
            requireInput(task.rule == RuleProofs.revision(task.request.locators, task.request.strategy), "Task rule differs from request")
            val missing = task.rule.requires.values.filter { it !in available }.distinct().sorted()
            val inherited = if (task.executionState == AnalysisExecutionState.INHERITED) inheritedEntry(task.request, task.rule, run.discovery, run.corpus, run.baseKnowledge, available, run.engineBuildId) else null
            if (task.executionState == AnalysisExecutionState.INHERITED) requireInput(inherited != null && task.resolution == inherited.resolution && task.waitingFor.isEmpty(), "Inherited class differs from base proof")
            else if (missing.isNotEmpty()) requireInput(task.resolution == null && task.waitingFor == missing && task.executionState == AnalysisExecutionState.WAITING_DEPENDENCY, "Invalid waiting class target")
            else {
                requireInput(task.resolution != null && task.waitingFor.isEmpty() && task.executionState == AnalysisExecutionState.EXECUTED, "Ready target was not executed")
                validateResolution(run, task.rule, task.resolution!!, available)
            }
            requireInput(task == makeTask(run.apk, task.request, task.rule, task.resolution, run.discovery, run.baseKnowledge, run.corpus, task.waitingFor, inherited != null, run.identityReferences), "Task target or semantic identity was altered")
        }
        if (verifyInputs) {
            listOfNotNull(run.apk, run.rulesFile, run.discoveryFile, run.baseFile, run.corpusFile).forEach(Digests::verify)
            requireInput(readRules(Path.of(run.rulesFile.path)) == run.rules, "Rules differ from frozen input")
            run.baseFile?.let { requireInput(KnowledgeFiles.read(Path.of(it.path)) == run.baseKnowledge, "Base package differs from frozen input") }
            run.discoveryFile?.let { requireInput(readDiscovery(Path.of(it.path), run.apk) == run.discovery, "Discovery differs from frozen input") }
            run.corpusFile?.let { requireInput(ManualCorpusFiles.read(Path.of(it.path)) == run.corpus, "Corpus differs from frozen input") }
            IdentityReferences.verifyFiles(run.identityReferences)
        }
        run
    }

    fun tasks(dir: Path, state: String? = null, offset: Int = 0, limit: Int = 20, services: Set<String> = emptySet()): AnalysisTaskPage {
        requireInput(offset >= 0 && limit > 0, "Invalid task pagination")
        requireInput(services.none(String::isBlank), "Service filters must be nonempty exact names")
        val run = readRun(dir)
        val latest = ReviewStore.latest(dir, run.runId)
        val decisions = decisions(dir, run, latest)
        val filter = (state ?: "UNREVIEWED").uppercase()
        requireInput(filter in TaskState.entries.map { it.name } + listOf("ALL", "WAITING_DEPENDENCY", "INHERITED"), "Unknown task state")
        val scoped = decisions.filter { decision -> RpcAnalysis.matchesServices(run.tasks.single { it.taskId == decision.taskId }, services) }
        val filtered = scoped.filter { d -> filter == "ALL" || if (filter in setOf("WAITING_DEPENDENCY", "INHERITED")) run.tasks.single { it.taskId == d.taskId }.executionState.name == filter else d.state.name == filter }.map { d ->
            AnalysisTaskView(run.tasks.single { it.taskId == d.taskId }, d.state, d.reason, latest[d.taskId]?.revisionId)
        }
        return AnalysisTaskPage(runId = run.runId, total = filtered.size, offset = offset, limit = limit, counts = counts(scoped),
            items = filtered.drop(offset).take(limit), carriedUnresolved = run.baseKnowledge?.unresolved.orEmpty(), anchors = run.anchorTasks)
    }

    fun targets(corpusPath: Path, runDir: Path? = null, state: String? = null, offset: Int = 0, limit: Int = 20): CorpusTargetPage {
        requireInput(offset >= 0 && limit > 0, "Invalid corpus pagination")
        val corpus = ManualCorpusFiles.read(corpusPath)
        val run = runDir?.let(::readRun)
        requireInput(run == null || run.corpus?.corpusId == corpus.corpusId, "Run belongs to another corpus")
        val rows = corpusViews(corpus, run, run?.let { decisions(runDir!!, it) }.orEmpty())
        val filter = state?.uppercase()?.takeUnless { it == "ALL" }
        requireInput(filter == null || filter in setOf("UNCONFIGURED", "WAITING_DEPENDENCY", "INHERITED") + TaskState.entries.map { it.name }, "Unknown corpus state")
        val selected = rows.filter { filter == null || it.state == filter }
        return CorpusTargetPage(corpusId = corpus.corpusId, runId = run?.runId, total = selected.size, offset = offset, limit = limit,
            counts = rows.groupingBy { it.state }.eachCount().toSortedMap(), items = selected.drop(offset).take(limit),
            additionalTasks = run?.tasks.orEmpty().filter { it.request.corpusTargetId == null }.map { it.taskId })
    }

    fun inspect(dir: Path, taskIds: Set<String>): List<EvidenceRecord> {
        val run = readRun(dir)
        requireInput(taskIds.isNotEmpty() && taskIds.all { id -> run.tasks.any { it.taskId == id } || run.anchorTasks.any { "anchor:${it.key}" == id } }, "Unknown or empty Analysis task selection")
        val refs = (run.tasks.filter { it.taskId in taskIds }.flatMap { AnalysisPolicy.allowedRefs(run, it) } +
            run.anchorTasks.filter { "anchor:${it.key}" in taskIds }.flatMap { task -> task.resolution?.let { anchorRefs(run, it) }.orEmpty() }).toSet()
        return ensureEvidence(dir, run, refs)
    }

    private fun ensureEvidence(dir: Path, run: AnalysisRun, refs: Set<ClassRef>): List<EvidenceRecord> {
        val existing = EvidenceFiles.available(dir, run.runId).map { it.ref }.toSet()
        val missing = (refs - existing).toMutableSet()
        val reusable = run.baseKnowledge?.let { base -> KnowledgeFiles.evidenceClosure(base)
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
        val accepted = decisions.filter { it.state == TaskState.ACCEPTED && run.tasks.single { task -> task.taskId == it.taskId }.executionState != AnalysisExecutionState.INHERITED }
        createNewDirectory(out)
        val entries = run.baseKnowledge?.entries.orEmpty().associateBy { it.semanticId }.toMutableMap()
        val pending = run.baseKnowledge?.unresolved.orEmpty().associateBy { it.entry.semanticId }.toMutableMap()
        val anchors = run.baseKnowledge?.anchors.orEmpty().associateBy { it.key }.toMutableMap()
        val updatedIds = accepted.map { it.semanticId!! }.toSet()
        run.baseFile?.let { baseFile ->
            val sourceRoot = Path.of(baseFile.path).parent
            (entries.values.filter { it.semanticId !in updatedIds } + pending.values.filter { it.entry.semanticId !in updatedIds }.map { it.entry })
                .forEach { KnowledgeFiles.copyEntry(sourceRoot, out, it) }
            anchors.values.forEach { KnowledgeFiles.copyAnchor(sourceRoot, out, it) }
        }
        run.anchorTasks.filter { it.resolution?.status == ResolutionStatus.UNIQUE && it.executionState != AnalysisExecutionState.INHERITED }.forEach { task ->
            val proof = task.resolution!!
            val evidence = anchorRefs(run, proof).sortedBy { it.descriptor }.map { ref -> EvidenceFiles.export(dir, run.runId, Identities.evidenceId(run.runId, ref), out) }
            anchors[task.key] = SupportAnchor(task.key, proof.uniqueEntity!!, task.rule, proof, evidence)
        }
        accepted.forEach { decision ->
            val task = run.tasks.single { it.taskId == decision.taskId }
            val review = decision.review!!
            val evidence = review.evidenceIds.sorted().map { EvidenceFiles.export(dir, run.runId, it, out) }
            entries[decision.semanticId!!] = KnowledgeEntry(decision.semanticId, decision.name!!, decision.target!!,
                RuleProofs.captures(task.resolution!!), task.rule.locators, evidence, review.rationale,
                "analysis:${run.runId}:${latest.getValue(task.taskId).revisionId}", task.rule, task.resolution)
            pending.remove(decision.semanticId)
        }
        val knowledge = KnowledgeFiles.write(out, VersionKnowledge(knowledgeId = "", artifact = run.apk,
            entries = entries.values.toList(), unresolved = pending.values.toList(), provenance = "analysis:${run.runId}", parentKnowledgeId = run.baseKnowledge?.knowledgeId,
            anchors = anchors.values.toList(), migrationSourceKnowledgeId = run.baseKnowledge?.migrationSourceKnowledgeId))
        MappingOutput.write(out.resolve("mapping.tiny"), knowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        val rpcCatalog = run.discovery?.takeIf { it.rpcCalls != null }?.let {
            RpcAnalysis.catalog(it, run.rpcCalls ?: it.rpcCalls.orEmpty(), run.tasks, decisions)
        }
        rpcCatalog?.let { JsonFiles.writeNew(out.resolve("rpc-catalog.json"), it) }
        val cached = EvidenceFiles.available(dir, run.runId)
        JsonFiles.writeNew(out.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "analysis-report", "runId" to run.runId,
            "knowledgeId" to knowledge.knowledgeId, "parentKnowledgeId" to knowledge.parentKnowledgeId, "apk" to run.apk,
            "reviewRevisions" to latest.mapValues { it.value.revisionId }, "tasks" to run.tasks, "decisions" to decisions,
            "counts" to counts(decisions), "acceptedUpdates" to accepted.size, "confirmed" to knowledge.entries.size,
            "resolutionCounts" to ResolutionStatus.entries.associateWith { status -> run.tasks.count { it.resolution?.status == status } },
            "executionCounts" to run.tasks.groupingBy { it.executionState }.eachCount(), "anchorTasks" to run.anchorTasks,
            "corpusId" to run.corpus?.corpusId, "corpusTargets" to run.corpus?.let { corpusViews(it, run, decisions) },
            "carriedConfirmed" to (knowledge.entries.size - accepted.size), "unresolved" to knowledge.unresolved.size,
            "identityReferences" to run.identityReferences?.map { reference -> mapOf("knowledgeId" to reference.knowledge.knowledgeId,
                "file" to reference.file, "mappingFile" to reference.mappingFile, "reportFile" to reference.reportFile,
                "acceptedIdentities" to accepted.filter { decision -> run.tasks.single { it.taskId == decision.taskId }.identitySourceKnowledgeId == reference.knowledge.knowledgeId }
                    .map { decision -> mapOf("semanticId" to decision.semanticId, "name" to decision.name, "binding" to decision.target) }) },
            "rpcCatalog" to rpcCatalog,
            "scan" to run.scan, "analysisMillis" to run.analysisMillis, "analysisDiagnostics" to run.analysisDiagnostics,
            "evidenceMetrics" to mapOf("scope" to "emitted_or_cached_evidence", "agentReadsMeasured" to false,
                "ownerApkPairs" to cached.map { it.ref }.distinct().size, "javaLines" to cached.sumOf { e -> Files.lines(dir.resolve(e.javaPath)).use { it.count() } },
                "smaliLines" to cached.sumOf { e -> e.smaliPath?.let { path -> Files.lines(dir.resolve(path)).use { it.count() } } ?: 0L }, "incompleteClasses" to cached.count { it.incomplete })))
        return AnalysisPublishResult(runId = run.runId, knowledgeId = knowledge.knowledgeId, acceptedUpdates = accepted.size,
            confirmed = knowledge.entries.size, unresolved = knowledge.unresolved.size, counts = counts(decisions),
            knowledgePath = out.resolve("knowledge.json").toString(), mappingPath = out.resolve("mapping.tiny").toString(), reportPath = out.resolve("report.json").toString(), anchors = knowledge.anchors.size)
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
        validateRpcCalls(discovery.rpcCalls, apk, discovery.classInventory)
        discovery.unresolvedPaths.orEmpty().forEach { path ->
            requireInput(path.source.owner.apkSha256 == apk.sha256 && discovery.classInventory[path.source.owner.descriptor] == path.source.owner.dexEntry,
                "Discovery unresolved path belongs to another APK/DEX")
        }
        requireInput(discovery.leads == createLeads(apk, discovery.profile, discovery.matches), "Discovery leads differ from frozen facts")
        requireInput((discovery.baseFile == null) == (discovery.baseKnowledge == null), "Incomplete discovery dependency base")
        discovery.baseKnowledge?.let { requireInput(it.artifact.sha256 == apk.sha256 && it.knowledgeId == KnowledgeFiles.id(it), "Discovery dependencies belong to another APK") }
        discovery.baseFile?.let { file ->
            Digests.verify(file)
            requireInput(KnowledgeFiles.read(Path.of(file.path)) == discovery.baseKnowledge, "Discovery dependency base changed")
        }
        discovery
    }

    private fun anchorRules(rules: AnalysisRuleFile, base: VersionKnowledge?): Map<String, RuleRevision> =
        (base?.anchors.orEmpty().associate { it.key to it.rule } + rules.anchors.associate { it.key to RuleProofs.revision(it.locators, it.strategy) }).toSortedMap()

    private fun validateDependencies(definitions: Map<String, RuleRevision>, targets: List<RuleRevision>, available: Collection<SupportAnchor>) {
        RuleProofs.validateDependencies(definitions, targets, available)
        val producers = available.associate { it.key to it.rule } + definitions
        (definitions.values + targets).forEach { rule ->
            StrategyRegistry.validateDependencyDefinitions(rule, producers)
        }
    }

    /** Reuse only proofs from this implementation with exactly the dependency revisions being consumed. */
    internal fun usableAnchors(base: VersionKnowledge?, definitions: Map<String, RuleRevision>, buildId: String): Map<String, SupportAnchor> {
        val result = base?.anchors.orEmpty().filter { it.rule == definitions[it.key] && it.resolution.engineBuildId == buildId }.associateBy { it.key }.toMutableMap()
        while (true) {
            val stale = result.filter { (_, anchor) -> !dependenciesMatch(anchor.rule, anchor.resolution, result) }.keys
            if (stale.isEmpty()) return result.toSortedMap()
            stale.forEach(result::remove)
        }
    }

    private fun dependenciesMatch(rule: RuleRevision, proof: Resolution, available: Map<String, SupportAnchor>): Boolean =
        proof.dependencies.keys == rule.requires.keys && rule.requires.all { (role, key) ->
            val anchor = available[key]
            anchor != null && proof.dependencies[role] == anchor
        }

    private fun inheritedEntry(item: AnalysisRuleItem, rule: RuleRevision, discovery: AnalysisDiscovery?, corpus: ManualCorpus?,
                               base: VersionKnowledge?, available: Map<String, SupportAnchor>, buildId: String): KnowledgeEntry? {
        val manual = item.corpusTargetId?.let { id -> corpus?.targets?.singleOrNull { it.targetId == id } }
        val lead = item.discoveryKey?.let { key -> discovery?.leads?.singleOrNull { it.key == key } }
        val expected = manual?.source ?: lead?.owner
        val entry = if (item.semanticId != null) base?.entries?.singleOrNull { it.semanticId == item.semanticId }
            else if (expected != null) base?.entries?.singleOrNull { it.binding == expected }
            else base?.entries?.singleOrNull { it.ruleRevision == rule }
        val proposed = item.proposedName ?: manual?.manualName ?: lead?.suggestedName
        val proof = entry?.resolution ?: return null
        return entry.takeIf { entry.ruleRevision == rule && proof.rule == rule && proof.engineBuildId == buildId &&
            proof.uniqueRef == entry.binding && (expected == null || expected == entry.binding) &&
            (proposed == null || proposed == entry.name) && dependenciesMatch(rule, proof, available) }
    }

    private fun validateResolution(run: AnalysisRun, rule: RuleRevision, proof: Resolution, available: Map<String, SupportAnchor>) {
        RuleProofs.validate(proof)
        requireInput(proof.rule == rule && proof.apkSha256 == run.apk.sha256 && proof.engineBuildId == run.engineBuildId, "Task proof differs from frozen rule, APK or implementation")
        requireInput(dependenciesMatch(rule, proof, available), "Task proof differs from the frozen dependency revisions")
        val refs = proof.matches.flatMap { listOf(it.owner) + it.relatedRefs + it.trace.map { trace -> trace.owner } }
        requireInput(refs.all { it.apkSha256 == run.apk.sha256 && run.classInventory[it.descriptor] == it.dexEntry }, "Resolution class/DEX identity mismatch")
        proof.unresolvedPaths.orEmpty().forEach { path ->
            requireInput(path.source.owner.apkSha256 == run.apk.sha256 && run.classInventory[path.source.owner.descriptor] == path.source.owner.dexEntry,
                "Unresolved path class/DEX identity mismatch")
        }
    }

    private fun validateRpcCalls(calls: List<RpcCallObservation>?, apk: Artifact, inventory: Map<String, String>) {
        calls.orEmpty().forEach { call ->
            val refs = listOf(call.source.owner) + call.requestTypes + call.responseTypes
            requireInput(call.codeUnitOffset >= 0 && refs.all { it.apkSha256 == apk.sha256 && inventory[it.descriptor] == it.dexEntry },
                "RPC catalogue contains an invalid source or Proto binding")
        }
    }

    private fun anchorRefs(run: AnalysisRun, proof: Resolution): Set<ClassRef> = buildSet {
        addAll(proof.candidates.map { it.ref })
        addAll(AnalysisPolicy.proofRefs(proof))
        proof.matches.mapNotNull { it.field?.call?.declaringType }.distinct().forEach { descriptor ->
            run.classInventory[descriptor]?.let { add(ClassRef(run.apk.sha256, descriptor, it)) }
        }
    }

    private fun corpusViews(corpus: ManualCorpus, run: AnalysisRun?, decisions: List<AnalysisDecision>): List<CorpusTargetView> = corpus.targets.map { target ->
        val task = run?.tasks?.singleOrNull { it.request.corpusTargetId == target.targetId }
        val decision = task?.let { selected -> decisions.single { it.taskId == selected.taskId } }
        val base = run?.baseKnowledge?.entries?.singleOrNull { it.binding == target.source }
        val state = when {
            task == null && base != null -> "INHERITED"
            task == null -> "UNCONFIGURED"
            task.executionState != AnalysisExecutionState.EXECUTED -> task.executionState.name
            else -> decision!!.state.name
        }
        CorpusTargetView(target, state, decision?.reason, task?.taskId, task?.resolution, base)
    }.sortedBy { it.target.targetId }

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
