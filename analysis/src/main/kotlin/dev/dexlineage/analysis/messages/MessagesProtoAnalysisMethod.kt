package dev.dexlineage.analysis.messages

import com.google.gson.JsonObject
import dev.dexlineage.analysis.*
import dev.dexlineage.io.*
import dev.dexlineage.messages.MessagesProtoArtifacts
import dev.dexlineage.messages.ProtoFieldCatalogue
import dev.dexlineage.model.*
import java.nio.file.Path

data class ProtoAnalysisTarget(val key: String, val fieldNumber: Int, val cardinality: String,
    val corpusTargetId: String? = null, val proposedName: String? = null)
data class ProtoTargetRow(val key: String, val fieldNumber: Int, val cardinality: String,
    val corpusTargetId: String?, val proposedName: String?, val observedTypes: List<ClassRef>,
    val resolution: String?, val state: String, val reason: String?)
data class ProtoAnalysisCounts(val configuredTargets: Int, val targetsWithObservedTypes: Int,
    val resolutions: Map<String, Int>, val decisions: Map<String, Int>)
data class ProtoAnalysisCatalog(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-proto-catalog",
    val discoveryId: String, val apk: Artifact, val fieldCatalogue: ProtoFieldCatalogue,
    val targets: List<ProtoTargetRow>, val counts: ProtoAnalysisCounts)

/** Fixed target declarations remain work even when discovery cannot establish a child type. */
internal object MessagesProtoAnalysisMethod : AnalysisMethod {
    override val id = "messages.proto-relations"
    override val seedRounds = 2

    internal fun targets(profile: AnalysisProfile): List<ProtoAnalysisTarget> = checkedInput("Proto relation targets") {
        val options = profile.method?.parameters ?: throw ValidationException("Proto analysis requires method settings")
        requireInput(options.keySet() == setOf("targets"), "Proto analysis requires only a targets array")
        val rows = options.getAsJsonArray("targets") ?: throw ValidationException("Proto analysis requires targets")
        val targets = rows.map { element ->
            val row = element.asJsonObject
            requireInput(row.keySet().all { it in setOf("key", "fieldNumber", "cardinality", "corpusTargetId", "proposedName") }, "Unknown Proto analysis target field")
            val number = row.get("fieldNumber")
            requireInput(number?.isJsonPrimitive == true && number.asJsonPrimitive.isNumber && number.asString.matches(Regex("[1-9][0-9]*")), "Proto fieldNumber must be a positive integer")
            val value = JsonFiles.gson.fromJson(row, ProtoAnalysisTarget::class.java)
            requireInput(value.key.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid Proto target key")
            requireInput(value.fieldNumber in 1..536870911, "Proto fieldNumber is outside the protobuf range")
            requireInput(value.cardinality in setOf("singular", "repeated"), "Proto cardinality must be singular or repeated")
            requireInput(value.corpusTargetId == null || value.corpusTargetId.isNotBlank(), "Empty Proto corpus target")
            requireInput(value.proposedName == null || value.proposedName.isNotBlank(), "Empty proposed Proto name")
            value
        }
        requireInput(targets.isNotEmpty() && targets.map { it.key }.distinct().size == targets.size, "Empty or duplicate Proto target keys")
        requireInput(targets.mapNotNull { it.corpusTargetId }.distinct().size == targets.count { it.corpusTargetId != null }, "Duplicate Proto corpus targets")
        targets
    }

    override fun validate(profile: AnalysisProfile) {
        val strategy = profile.strategy ?: throw ValidationException("Proto relation analysis requires a discovery strategy")
        requireInput(strategy.strategyId == "messages.proto-fields", "Proto relation analysis requires messages.proto-fields discovery")
        requireInput(strategy.resultKind == EntityKind.CLASS && strategy.requires.keys == setOf("parent") && strategy.parameters.size() == 0,
            "Proto discovery requires one parent CLASS dependency and no field selector")
        requireInput(profile.nameCapture == null && profile.locatorTemplate == null && profile.strategyTemplate == null && profile.parameterCaptures.isEmpty(),
            "Proto analysis owns its declared target drafts")
        targets(profile)
    }

    override fun corpusTargetIds(profile: AnalysisProfile): Set<String> = targets(profile).mapNotNull { it.corpusTargetId }.toSet()

    override fun leads(apk: Artifact, profile: AnalysisProfile, facts: List<MatchFact>): List<DiscoveryLead> = facts
        .filter { it.status != MatchStatus.FAIL }.groupBy { it.owner }.map { (owner, matches) ->
            val captures = matches.first().captures.filter { (key, value) -> matches.all { it.captures[key] == value } }.toSortedMap()
            DiscoveryLead(Digests.text("analysis-proto-lead\n${apk.sha256}\n${owner.dexEntry}\n${owner.descriptor}"), owner, null, captures, matches)
        }.sortedBy { it.key }

    override fun drafts(profile: AnalysisProfile, leads: List<DiscoveryLead>): List<AnalysisRuleItem> = targets(profile).map { target ->
        AnalysisRuleItem(target.key, proposedName = target.proposedName, corpusTargetId = target.corpusTargetId,
            strategy = StrategySpec("messages.proto-field-type", JsonObject().apply {
                addProperty("fieldNumber", target.fieldNumber); addProperty("cardinality", target.cardinality)
            }, EntityKind.CLASS, profile.strategy!!.requires))
    }

    override fun taskDetails(task: AnalysisTask): JsonObject = JsonObject().apply {
        add("fieldNumber", task.rule.parameters.get("fieldNumber")); add("cardinality", task.rule.parameters.get("cardinality"))
        addProperty("parentAnchor", task.rule.requires.getValue("parent"))
    }

    override fun validateArtifacts(artifacts: List<ScenarioArtifactRef>, compatibility: JsonObject?, apk: Artifact, inventory: Map<String, String>) {
        if (artifacts.isEmpty()) return // Inherited or waiting runs have no new matching catalogue.
        val catalogue = MessagesProtoArtifacts.read(artifacts) ?: throw ValidationException("Missing Proto field catalogue")
        val refs = listOf(catalogue.parent) + catalogue.fields.mapNotNull { it.relatedType } +
            catalogue.metadata.flatMap { listOfNotNull(it.source.owner, it.factory?.owner) } + catalogue.unresolvedPaths.map { it.source.owner }
        requireInput(catalogue.apkSha256 == apk.sha256 && refs.all { it.apkSha256 == apk.sha256 && inventory[it.descriptor] == it.dexEntry },
            "Proto catalogue belongs to another APK or DEX")
    }

    override fun discoveryArtifacts(discovery: AnalysisDiscovery, out: Path): List<ScenarioArtifactRef> = write(out, catalog(discovery))
    override fun validateDiscoveryArtifacts(discovery: AnalysisDiscovery, out: Path): List<ScenarioArtifactRef> = validate(out, catalog(discovery))
    override fun publicationArtifacts(run: AnalysisRun, decisions: List<AnalysisDecision>, out: Path): List<ScenarioArtifactRef> {
        val discovery = run.discovery ?: return emptyList()
        val refs = run.methodArtifacts.orEmpty().ifEmpty { discovery.methodArtifacts.orEmpty() }
        return AnalysisMethods.copyArtifacts(refs, out).orEmpty() + write(out, catalog(discovery, refs, run.tasks, decisions))
    }
    override fun validatePublicationArtifacts(run: AnalysisRun, decisions: List<AnalysisDecision>, out: Path): List<ScenarioArtifactRef> {
        val discovery = run.discovery ?: return emptyList()
        val refs = run.methodArtifacts.orEmpty().ifEmpty { discovery.methodArtifacts.orEmpty() }
        return AnalysisMethods.validateCopiedArtifacts(refs, out) + validate(out, catalog(discovery, refs, run.tasks, decisions))
    }

    internal fun catalog(discovery: AnalysisDiscovery, refs: List<ScenarioArtifactRef> = discovery.methodArtifacts.orEmpty(),
                         tasks: List<AnalysisTask> = emptyList(), decisions: List<AnalysisDecision> = emptyList()): ProtoAnalysisCatalog {
        val raw = MessagesProtoArtifacts.read(refs) ?: throw ValidationException("Missing Proto field catalogue")
        val taskMap = tasks.associateBy { it.taskId }; val decisionMap = decisions.associateBy { it.taskId }
        val rows = targets(discovery.profile).map { target ->
            val task = taskMap[target.key]; val decision = decisionMap[target.key]
            ProtoTargetRow(target.key, target.fieldNumber, target.cardinality, target.corpusTargetId, target.proposedName,
                raw.fields.filter { it.fieldNumber == target.fieldNumber && it.cardinality == target.cardinality }.mapNotNull { it.relatedType }.distinct().sortedBy { it.descriptor },
                task?.resolution?.status?.name, decision?.state?.name ?: task?.executionState?.name ?: "NOT_EXECUTED", decision?.reason ?: task?.invalidReason)
        }
        return ProtoAnalysisCatalog(discoveryId = discovery.discoveryId, apk = discovery.apk, fieldCatalogue = raw, targets = rows,
            counts = ProtoAnalysisCounts(rows.size, rows.count { it.observedTypes.isNotEmpty() }, rows.mapNotNull { it.resolution }.groupingBy { it }.eachCount().toSortedMap(),
                rows.groupingBy { it.state }.eachCount().toSortedMap()))
    }
    private fun write(out: Path, value: ProtoAnalysisCatalog): List<ScenarioArtifactRef> {
        val path = out.resolve("proto-catalog.json"); JsonFiles.writeNew(path, value)
        return listOf(ScenarioArtifactRef("messages.proto-analysis-catalog", path.toAbsolutePath().toString(), Digests.file(path)))
    }
    private fun validate(out: Path, value: ProtoAnalysisCatalog): List<ScenarioArtifactRef> {
        val path = out.resolve("proto-catalog.json")
        requireInput(JsonFiles.read(path, ProtoAnalysisCatalog::class.java) == value, "Proto catalogue differs from frozen facts and decisions")
        return listOf(ScenarioArtifactRef("messages.proto-analysis-catalog", path.toAbsolutePath().toString(), Digests.file(path)))
    }
}
