package dev.dexlineage.analysis.workspace

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.dexlineage.analysis.*
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.rules.StrategyRegistry
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

/** Calls the existing Analysis owner and validates durable output before recording completion. */
internal object AnalysisWorkspaceActions : WorkspaceActions {
    override fun implementationId(): String {
        val source = Path.of(WorkspaceService::class.java.protectionDomain.codeSource.location.toURI())
        return workspaceImplementationFingerprint(source, ResolutionEngine.buildId())
    }

    override fun inputs(methodId: String, configPath: Path): WorkspaceInputs = checkedInput("workspace configuration") {
        val configFile = Digests.artifact(configPath)
        val json = JsonParser.parseString(Files.readString(configPath)).asJsonObject
        requireInput(json["schemaVersion"]?.asInt == SCHEMA_VERSION, "Expected schemaVersion $SCHEMA_VERSION")
        requireInput(json.keySet().all { it in setOf("schemaVersion", "apk", "baseKnowledge", "referenceKnowledge", "profile", "seedRules") }, "Unknown workspace configuration field")
        fun text(key: String): String? = json.get(key)?.takeUnless { it.isJsonNull }?.asString?.also { requireInput(it.isNotBlank(), "Empty workspace $key") }
        val config = WorkspaceConfig(apk = text("apk") ?: throw ValidationException("Workspace requires apk"),
            profile = text("profile") ?: throw ValidationException("Workspace requires profile"), baseKnowledge = text("baseKnowledge"), seedRules = text("seedRules"),
            referenceKnowledge = json.getAsJsonArray("referenceKnowledge")?.map { it.asString.also { value -> requireInput(value.isNotBlank(), "Empty identity reference path") } }.orEmpty())
        fun path(value: String) = configPath.parent.resolve(value).normalize().toAbsolutePath()
        val apk = Digests.artifact(path(config.apk))
        val baseFile = config.baseKnowledge?.let { Digests.artifact(path(it)) }
        val base = baseFile?.let { checkedPackage(Path.of(it.path), apk) }
        val referenceFiles = config.referenceKnowledge.map { Digests.artifact(path(it)) }
        IdentityReferences.load(referenceFiles.map { Path.of(it.path) }, apk, base)
        val plan = AnalysisMethods.prepareConfig(methodId, configPath)
        validateSeedPlan(plan, base, ResolutionEngine.buildId())
        val files = (listOf(configFile, apk) + plan.inputArtifacts + listOfNotNull(baseFile).flatMap(::packageFiles) + referenceFiles.flatMap(::packageFiles))
            .distinctBy { it.path }.sortedBy { it.path }
        files.forEach(Digests::verify)
        WorkspaceInputs(configFile, config, apk, baseFile, referenceFiles, plan, files, implementationId(), ResolutionEngine.buildId())
    }

    /** Validate the finite plan, without executing facts or guessing whether a rule will be unique. */
    internal fun validateSeedPlan(plan: AnalysisMethodPlan, base: VersionKnowledge?, buildId: String) {
        val target = RuleProofs.revision(if (plan.profile.strategy == null) listOf(plan.profile.discovery) else emptyList(), plan.profile.strategy)
        var definitions = base?.anchors.orEmpty().associate { it.key to it.rule }
        var possible = AnalysisService.usableAnchors(base, definitions, buildId).mapValues { it.value.rule }
        val steps = if (plan.seedSteps.isEmpty()) listOf<AnalysisRuleFile?>(null) else plan.seedSteps
        for (step in steps) {
            definitions = definitions + step?.anchors.orEmpty().associate { it.key to RuleProofs.revision(it.locators, it.strategy) }
            RuleProofs.validateDependencies(definitions, listOf(target), base?.anchors.orEmpty())
            (definitions.values + target).forEach { rule -> StrategyRegistry.validateDependencyDefinitions(rule, definitions) }
            possible = possible.filter { (key, rule) -> definitions[key] == rule }
            while (true) {
                val retained = possible.filter { (_, rule) -> rule.requires.values.all { it in possible } }
                if (retained.size == possible.size) break
                possible = retained
            }
            if (step != null) possible = possible + definitions.filter { (_, rule) -> rule.requires.values.all { it in possible } }
        }
        requireInput(target.requires.values.all { it in possible },
            "Declared seed rounds cannot reach discovery dependencies: ${target.requires.values.filter { it !in possible }.joinToString()}")
    }

    private fun packageFiles(file: Artifact): List<Artifact> {
        val path = Path.of(file.path)
        val value = KnowledgeFiles.read(path)
        val root = path.parent
        val proof = KnowledgeFiles.evidenceClosure(value).flatMap { listOfNotNull(it.javaPath, it.smaliPath) }
        val reportPath = root.resolve("report.json")
        val report = JsonParser.parseString(Files.readString(reportPath)).asJsonObject
        val extra = artifactRefs(report, root).map { Path.of(it.path) }
        requireInput(extra.all { it.toAbsolutePath().normalize().startsWith(root.toAbsolutePath().normalize()) }, "Package method artifact escapes its root")
        return (listOf(path, root.resolve("mapping.tiny"), reportPath) + proof.map(root::resolve) + extra).distinct().map(Digests::artifact)
    }

    override fun discoveryWaiting(context: WorkspaceContext): List<String> {
        val base = context.base()?.let(KnowledgeFiles::read)
        val available = AnalysisService.usableAnchors(base, base?.anchors.orEmpty().associate { it.key to it.rule }, context.record.inputs.engineBuildId)
        return context.record.inputs.method.profile.strategy?.requires?.values.orEmpty().filter { it !in available }.distinct().sorted()
    }

    override fun execute(context: WorkspaceContext, stage: WorkspaceStage, attempt: Path): WorkspaceProduct {
        val apk = Path.of(context.record.inputs.apk.path)
        when (stage.kind) {
            WorkspaceStageKind.SEED -> {
                val rules = context.root.resolve("inputs/seed-${stage.seedIndex!! + 1}.json")
                AnalysisService.prepare(apk, rules, attempt.resolve("run"), context.base())
                AnalysisService.publish(attempt.resolve("run"), attempt.resolve("published"))
            }
            WorkspaceStageKind.DISCOVERY -> AnalysisService.discover(apk, context.root.resolve("inputs/profile.json"), attempt.resolve("discovery"), context.base())
            WorkspaceStageKind.PREPARE -> AnalysisService.prepare(apk,
                context.resolve(context.products.getValue("discover").rulesPath!!), attempt.resolve("run"), context.base(),
                referenceKnowledgePaths = context.record.inputs.referenceKnowledge.map { Path.of(it.path) })
            WorkspaceStageKind.PACKET -> {
                val dir = context.runDir()
                val selected = AnalysisMethods.selectedReviewTaskIds(AnalysisService.readRun(dir))
                ReviewPackets.write(dir, selected, attempt.resolve("packet"))
            }
            WorkspaceStageKind.REVIEW_HEADS -> {
                val dir = context.runDir()
                val run = AnalysisService.readRun(dir)
                val heads = ReviewStore.latest(dir, run.runId).mapValues { it.value.revisionId }
                writeWorkspaceJson(attempt.resolve("review-heads.json"), mapOf("schemaVersion" to SCHEMA_VERSION,
                    "runId" to run.runId, "reviewRevisions" to heads))
                ReviewStore.fromSnapshot(dir, run.runId, attempt.resolve("review-heads.json"))
            }
            WorkspaceStageKind.PUBLICATION -> AnalysisService.publish(context.runDir(), attempt.resolve("published"),
                context.resolve(context.products.getValue("review-heads").reviewHeadsPath!!))
        }
        return validate(context, stage, attempt)
    }

    override fun validate(context: WorkspaceContext, stage: WorkspaceStage, attempt: Path): WorkspaceProduct = checkedInput("workspace ${stage.id} output") {
        val apk = context.record.inputs.apk
        fun run(path: Path, rulesPath: Path, references: Boolean): AnalysisRun {
            val value = AnalysisService.readRun(path)
            requireInput(value.apk == apk && value.engineBuildId == context.record.inputs.engineBuildId, "Stage run APK or implementation mismatch")
            requireInput(value.rulesFile == Digests.artifact(rulesPath), "Stage run used a different rule input")
            requireInput(value.baseFile == context.base()?.let(Digests::artifact), "Stage run used a different base knowledge")
            requireInput(value.identityReferences.orEmpty().map { it.file }.toSet() ==
                (if (references) context.record.inputs.referenceKnowledge.toSet() else emptySet()), "Stage run used different identity references")
            return value
        }
        when (stage.kind) {
            WorkspaceStageKind.SEED -> {
                val dir = attempt.resolve("run")
                val value = run(dir, context.root.resolve("inputs/seed-${stage.seedIndex!! + 1}.json"), false)
                requireInput(value.tasks.isEmpty(), "Workspace seed stage cannot perform class semantic review")
                val published = validatePublication(dir, attempt.resolve("published"), value, null)
                WorkspaceProduct(runPath = context.relative(dir), runId = value.runId,
                    knowledgePath = context.relative(attempt.resolve("published/knowledge.json")), knowledgeId = published.knowledgeId)
            }
            WorkspaceStageKind.DISCOVERY -> {
                val path = attempt.resolve("discovery/discovery.json")
                val value = AnalysisService.readDiscovery(path, apk)
                requireInput(value.engineBuildId == context.record.inputs.engineBuildId && value.profile == context.record.inputs.method.profile &&
                    value.profileSource == Digests.artifact(context.root.resolve("inputs/profile.json")) && value.baseFile == context.base()?.let(Digests::artifact),
                    "Discovery used different frozen inputs")
                AnalysisMethods.forProfile(value.profile).validateDiscoveryArtifacts(value, path.parent)
                val items = AnalysisMethods.forProfile(value.profile).drafts(value.profile, value.leads)
                val rulesPath = path.parent.resolve("rules.json")
                if (items.isEmpty()) requireInput(!Files.exists(rulesPath), "Empty discovery has unexpected target rules")
                else requireInput(AnalysisService.readRules(rulesPath) == AnalysisRuleFile(discovery = Digests.artifact(path),
                    minConfidence = value.profile.minConfidence, items = items), "Discovery drafts differ from method facts")
                WorkspaceProduct(discoveryPath = context.relative(path), rulesPath = rulesPath.takeIf { items.isNotEmpty() }?.let(context::relative))
            }
            WorkspaceStageKind.PREPARE -> {
                val dir = attempt.resolve("run")
                val value = run(dir, context.resolve(context.products.getValue("discover").rulesPath!!), true)
                requireInput(value.discoveryFile == Digests.artifact(context.resolve(context.products.getValue("discover").discoveryPath!!)), "Run discovery differs from the completed discovery stage")
                WorkspaceProduct(runPath = context.relative(dir), runId = value.runId)
            }
            WorkspaceStageKind.PACKET -> {
                val dir = context.runDir()
                val selected = AnalysisMethods.selectedReviewTaskIds(AnalysisService.readRun(dir))
                val result = ReviewPackets.validate(attempt.resolve("packet"), dir, selected)
                WorkspaceProduct(runPath = context.relative(dir), runId = result.runId, packetPath = context.relative(attempt.resolve("packet")),
                    selectedTaskIds = selected.sorted())
            }
            WorkspaceStageKind.REVIEW_HEADS -> {
                val dir = context.runDir()
                val value = AnalysisService.readRun(dir)
                val path = attempt.resolve("review-heads.json")
                val heads = ReviewStore.fromSnapshot(dir, value.runId, path)
                val selected = AnalysisMethods.selectedReviewTaskIds(value)
                val decisions = AnalysisService.decisions(dir, value, heads)
                requireInput(decisions.none { it.taskId in selected && it.state == TaskState.UNREVIEWED } &&
                    value.tasks.none { it.taskId in selected && it.executionState == AnalysisExecutionState.WAITING_DEPENDENCY }, "Frozen reviews leave selected tasks unreviewed or waiting")
                WorkspaceProduct(runPath = context.relative(dir), runId = value.runId, reviewHeadsPath = context.relative(path), selectedTaskIds = selected.sorted())
            }
            WorkspaceStageKind.PUBLICATION -> {
                val dir = context.runDir()
                val value = AnalysisService.readRun(dir)
                val headsPath = context.resolve(context.products.getValue("review-heads").reviewHeadsPath!!)
                val published = validatePublication(dir, attempt.resolve("published"), value, headsPath)
                WorkspaceProduct(runPath = context.relative(dir), runId = value.runId,
                    knowledgePath = context.relative(attempt.resolve("published/knowledge.json")), knowledgeId = published.knowledgeId)
            }
        }
    }

    override fun reviewGate(runDir: Path): WorkspaceReviewGate {
        val run = AnalysisService.readRun(runDir)
        val selected = AnalysisMethods.selectedReviewTaskIds(run)
        requireInput(selected.all { id -> run.tasks.any { it.taskId == id } }, "Method selected an unknown review task")
        val views = AnalysisService.tasks(runDir, "ALL", limit = Int.MAX_VALUE).items.filter { it.task.taskId in selected }
        return WorkspaceReviewGate(selected.sorted(), views.filter { it.state == TaskState.UNREVIEWED }.map { it.task.taskId }.sorted(),
            views.filter { it.task.executionState == AnalysisExecutionState.WAITING_DEPENDENCY }.map { it.task.taskId }.sorted())
    }

    private fun validatePublication(runDir: Path, out: Path, run: AnalysisRun, headsPath: Path?): VersionKnowledge {
        val value = checkedPackage(out.resolve("knowledge.json"), run.apk)
        val report = JsonParser.parseString(Files.readString(out.resolve("report.json"))).asJsonObject
        val heads = headsPath?.let { ReviewStore.fromSnapshot(runDir, run.runId, it) } ?: ReviewStore.latest(runDir, run.runId)
        val decisions = AnalysisService.decisions(runDir, run, heads)
        requireInput(report["runId"]?.asString == run.runId && report["reviewRevisions"] == JsonFiles.gson.toJsonTree(heads.mapValues { it.value.revisionId }) &&
            report["decisions"] == JsonFiles.gson.toJsonTree(decisions) && report["tasks"] == JsonFiles.gson.toJsonTree(run.tasks),
            "Publication report differs from its frozen run or Review heads")
        requireInput(value.parentKnowledgeId == run.baseKnowledge?.knowledgeId, "Publication changed its base knowledge revision")
        val accepted = decisions.filter { it.state == TaskState.ACCEPTED }.associateBy { it.semanticId!! }
        val expectedEntries = run.baseKnowledge?.entries.orEmpty().associateBy { it.semanticId }
        requireInput(value.entries.map { it.semanticId }.toSet() == expectedEntries.keys + accepted.keys, "Publication omitted or invented confirmed entries")
        value.entries.forEach { entry ->
            val update = accepted[entry.semanticId]
            if (update == null) requireInput(entry == expectedEntries[entry.semanticId], "Publication altered an untouched base entry")
            else {
                val task = run.tasks.single { it.taskId == update.taskId }
                requireInput(entry.binding == update.target && entry.name == update.name && entry.ruleRevision == task.rule && entry.resolution == task.resolution,
                    "Published binding lacks its accepted current matching result")
            }
        }
        requireInput(value.unresolved == run.baseKnowledge?.unresolved.orEmpty().filter { it.entry.semanticId !in accepted }.sortedBy { it.entry.semanticId },
            "Publication changed unresolved history")
        val anchors = run.baseKnowledge?.anchors.orEmpty().associate { it.key to Triple(it.binding, it.rule, it.resolution) }.toMutableMap()
        run.anchorTasks.filter { it.resolution?.status == ResolutionStatus.UNIQUE }.forEach { task ->
            anchors[task.key] = Triple(task.resolution!!.uniqueEntity!!, task.rule, task.resolution)
        }
        requireInput(value.anchors.associate { it.key to Triple(it.binding, it.rule, it.resolution) } == anchors, "Publication omitted or changed auxiliary anchor proofs")
        val refs = artifactRefs(report, out)
        requireInput(refs.all { Path.of(it.path).toAbsolutePath().normalize().startsWith(out.toAbsolutePath().normalize()) }, "Published method artifact escapes output")
        AnalysisMethods.validateArtifacts(refs, null, run.discovery?.profile, run.apk, run.classInventory)
        requireInput(refs == AnalysisMethods.forRun(run).validatePublicationArtifacts(run, decisions, out), "Publication method outputs are incomplete or changed")
        return value
    }

    private fun checkedPackage(path: Path, apk: Artifact): VersionKnowledge {
        val value = KnowledgeFiles.read(path)
        requireInput(value.artifact.sha256 == apk.sha256, "Workspace knowledge belongs to another APK")
        val report = JsonParser.parseString(Files.readString(path.parent.resolve("report.json"))).asJsonObject
        requireInput(report["schemaVersion"]?.asInt == SCHEMA_VERSION && report["knowledgeId"]?.asString == value.knowledgeId, "Knowledge package report is incomplete or inconsistent")
        MappingOutput.verifyContents(path.parent.resolve("mapping.tiny"), value.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        artifactRefs(report, path.parent).forEach { Digests.verify(Artifact(it.path, it.sha256)) }
        return value
    }

    internal fun artifactRefs(report: JsonObject, packageRoot: Path): List<ScenarioArtifactRef> {
        val root = packageRoot.toAbsolutePath().normalize()
        return report.getAsJsonArray("methodArtifacts")?.map {
            val ref = JsonFiles.gson.fromJson(it, ScenarioArtifactRef::class.java)
            val raw = Path.of(ref.path)
            val resolved = (if (raw.isAbsolute) raw else root.resolve(raw)).toAbsolutePath().normalize()
            requireInput(resolved.startsWith(root), "Package method artifact escapes its root")
            ref.copy(path = resolved.toString())
        }.orEmpty()
    }
}

/** Stable between installed JARs and Gradle class directories; ZIP times and absolute paths are not code. */
internal fun workspaceImplementationFingerprint(source: Path, matchingBuildId: String): String {
    fun ownClass(name: String) = name.startsWith("dev/dexlineage/") && name.endsWith(".class")
    val classes = if (Files.isDirectory(source)) Files.walk(source).use { paths ->
        paths.filter { Files.isRegularFile(it) }.map { source.relativize(it).toString().replace('\\', '/') to it }
            .filter { ownClass(it.first) }.toList().associate { it.first to Digests.file(it.second) }
    } else ZipFile(source.toFile()).use { zip -> zip.entries().asSequence().filter { !it.isDirectory && ownClass(it.name) }
        .associate { it.name to zip.getInputStream(it).use { input -> Digests.bytes(input.readAllBytes()) } } }
    requireInput(classes.isNotEmpty(), "Workspace implementation contains no project classes")
    val code = classes.toSortedMap().entries.joinToString("\n") { "${it.key}\t${it.value}" }
    return Digests.text("analysis-workspace\n$TOOL_VERSION\n$matchingBuildId\n$code")
}
