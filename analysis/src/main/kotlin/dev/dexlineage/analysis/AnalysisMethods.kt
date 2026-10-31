package dev.dexlineage.analysis

import dev.dexlineage.analysis.messages.*

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.RuleEngine
import dev.dexlineage.rules.RuleJson
import dev.dexlineage.rules.StrategyRegistry
import dev.dexlineage.knowledge.RuleProofs
import java.nio.file.Files
import java.nio.file.Path

data class AnalysisMethodPlan(val methodId: String, val profileFile: Artifact, val profile: AnalysisProfile,
    val seedRulesFile: Artifact?, val seedSteps: List<AnalysisRuleFile>, val inputArtifacts: List<Artifact>)

/** A compiled analysis method interprets facts and proposes work. It cannot publish a binding. */
interface AnalysisMethod {
    val id: String
    val seedRounds: Int get() = 0
    fun validate(profile: AnalysisProfile)
    fun leads(apk: Artifact, profile: AnalysisProfile, facts: List<MatchFact>): List<DiscoveryLead>
    fun drafts(profile: AnalysisProfile, leads: List<DiscoveryLead>): List<AnalysisRuleItem>
    fun corpusTargetIds(profile: AnalysisProfile): Set<String> = emptySet()
    fun validateArtifacts(artifacts: List<ScenarioArtifactRef>, compatibility: JsonObject?, apk: Artifact, inventory: Map<String, String>) {}
    fun discoveryArtifacts(discovery: AnalysisDiscovery, out: Path): List<ScenarioArtifactRef> = emptyList()
    fun validateDiscoveryArtifacts(discovery: AnalysisDiscovery, out: Path): List<ScenarioArtifactRef> = emptyList()
    fun publicationArtifacts(run: AnalysisRun, decisions: List<AnalysisDecision>, out: Path): List<ScenarioArtifactRef> = emptyList()
    fun validatePublicationArtifacts(run: AnalysisRun, decisions: List<AnalysisDecision>, out: Path): List<ScenarioArtifactRef> = emptyList()
    fun selectedReviewTaskIds(run: AnalysisRun): Set<String> = run.tasks.map { it.taskId }.toSet()
    fun matches(task: AnalysisTask, filters: Map<String, Set<String>>): Boolean {
        requireInput(filters.isEmpty(), "Method $id does not support task filters")
        return true
    }
    fun taskDetails(task: AnalysisTask): JsonObject = JsonObject()
}

object AnalysisMethods {
    private val methods: Map<String, AnalysisMethod> = register(listOf(ProfileAnalysisMethod, MessagesGrpcAnalysisMethod, MessagesProtoAnalysisMethod))
    internal fun register(values: List<AnalysisMethod>): Map<String, AnalysisMethod> {
        requireInput(values.all { it.id.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]*")) }, "Invalid Analysis method ID")
        requireInput(values.map { it.id }.distinct().size == values.size, "Duplicate Analysis method ID")
        return values.associateBy { it.id }
    }
    fun get(methodId: String): AnalysisMethod = methods[methodId] ?: throw ValidationException("Unknown Analysis method: $methodId")
    fun forProfile(profile: AnalysisProfile): AnalysisMethod = get(profile.method?.methodId ?: "profile")
    fun forRun(run: AnalysisRun): AnalysisMethod = run.discovery?.profile?.let(::forProfile) ?: get("profile")
    fun selectedReviewTaskIds(run: AnalysisRun): Set<String> = forRun(run).selectedReviewTaskIds(run)

    fun prepareConfig(methodId: String, configPath: Path): AnalysisMethodPlan = checkedInput("Analysis method configuration") {
        val config = JsonParser.parseString(Files.readString(configPath)).asJsonObject
        requireInput(config.get("schemaVersion")?.asInt == SCHEMA_VERSION, "Expected schemaVersion $SCHEMA_VERSION")
        requireInput(config.keySet().all { it in setOf("schemaVersion", "apk", "baseKnowledge", "referenceKnowledge", "profile", "seedRules", "corpus") }, "Unknown Analysis method configuration field")
        val method = get(methodId)
        fun path(key: String): Path? = config.get(key)?.takeUnless { it.isJsonNull }?.asString?.let { configPath.toAbsolutePath().parent.resolve(it).normalize() }
        val profileFile = path("profile")?.let(Digests::artifact) ?: throw ValidationException("Analysis method requires profile")
        val read = readProfile(Path.of(profileFile.path))
        requireInput(read.method == null || read.method.methodId == methodId, "Profile belongs to another Analysis method")
        val profile = read.copy(method = read.method ?: AnalysisMethodSpec(methodId), compatibility = null)
        method.validate(profile)
        val seedFile = path("seedRules")?.let(Digests::artifact)
        requireInput((method.seedRounds == 0) == (seedFile == null), if (method.seedRounds == 0) "Method $methodId does not use seed rules" else "Method $methodId requires seedRules")
        val seed = seedFile?.let { AnalysisService.readRules(Path.of(it.path)) }
        requireInput(seed == null || seed.items.isEmpty() && seed.anchors.isNotEmpty() && seed.discovery == null, "Seed rules must contain only anchor definitions")
        AnalysisMethodPlan(methodId, profileFile, profile, seedFile, if (seed == null) emptyList() else List(method.seedRounds) { seed },
            listOfNotNull(profileFile, seedFile))
    }

    fun readProfile(path: Path): AnalysisProfile = checkedInput("Analysis discovery profile") {
        val json = JsonParser.parseString(Files.readString(path)).asJsonObject
        AnalysisProfileWire.validateFields(json)
        if (json.get("strategy")?.isJsonNull != false) RuleJson.validateLocator(json.get("discovery"))
        else validateStrategyJson(json.getAsJsonObject("strategy"))
        json.get("strategyTemplate")?.takeUnless { it.isJsonNull }?.asJsonObject?.let(::validateStrategyJson)
        json.get("locatorTemplate")?.takeUnless { it.isJsonNull }?.let { RuleJson.validateLocator(it, template = true) }
        val profile = JsonFiles.read(path, AnalysisProfile::class.java)
        requireInput(profile.id.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,79}")), "Invalid profile ID")
        val level: Confidence? = profile.minConfidence
        requireInput(level != null, "Invalid confidence threshold")
        if (profile.strategy == null) RuleEngine.validate(profile.discovery) else {
            requireInput(profile.discovery.kind.isBlank(), "Discovery cannot specify both locator and strategy")
            StrategyRegistry.validate(RuleProofs.revision(emptyList(), profile.strategy))
        }
        forProfile(profile).validate(profile)
        profile
    }

    internal fun validateArtifacts(refs: List<ScenarioArtifactRef>?, compatibility: JsonObject?, profile: AnalysisProfile?, apk: Artifact, inventory: Map<String, String>) {
        refs.orEmpty().forEach { requireInput(it.kind.isNotBlank(), "Empty method artifact kind"); Digests.verify(Artifact(it.path, it.sha256)) }
        (profile?.let(::forProfile) ?: get("profile")).validateArtifacts(refs.orEmpty(), compatibility, apk, inventory)
    }

    internal fun copyArtifacts(refs: List<ScenarioArtifactRef>, out: Path): List<ScenarioArtifactRef>? {
        if (refs.isEmpty()) return null
        val folder = out.resolve("method-artifacts"); Files.createDirectories(folder)
        return refs.distinct().mapIndexed { index, ref ->
            Digests.verify(Artifact(ref.path, ref.sha256))
            val path = folder.resolve("$index-${ref.sha256}.json")
            if (!Files.exists(path)) Files.copy(Path.of(ref.path), path)
            ScenarioArtifactRef(ref.kind, path.toAbsolutePath().normalize().toString(), ref.sha256)
        }
    }

    internal fun validateCopiedArtifacts(refs: List<ScenarioArtifactRef>, out: Path): List<ScenarioArtifactRef> = refs.distinct().mapIndexed { index, ref ->
        val path = out.resolve("method-artifacts/$index-${ref.sha256}.json").toAbsolutePath().normalize()
        Digests.verify(Artifact(path.toString(), ref.sha256))
        ScenarioArtifactRef(ref.kind, path.toString(), ref.sha256)
    }

    private fun validateStrategyJson(value: JsonObject) {
        requireInput(value.keySet().all { it in setOf("strategyId", "parameters", "resultKind", "requires") }, "Unknown strategy field")
    }
}

private object ProfileAnalysisMethod : AnalysisMethod {
    override val id = "profile"
    override fun validate(profile: AnalysisProfile) {
        requireInput(profile.method?.parameters?.size() in listOf(null, 0), "Profile method has no method-specific parameters")
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
    }
    override fun leads(apk: Artifact, profile: AnalysisProfile, facts: List<MatchFact>): List<DiscoveryLead> = facts
        .filter { it.status != MatchStatus.FAIL }.groupBy { it.owner }.entries.sortedBy { it.key.descriptor }.flatMap { (owner, ownerFacts) ->
            val passing = ownerFacts.filter { it.status == MatchStatus.PASS }
            val groups = if (passing.isEmpty()) listOf(emptyMap<String, String>() to ownerFacts) else passing.groupBy { it.captures.toSortedMap() }.toList()
            groups.map { (captures, matches) -> DiscoveryLead(Digests.text("analysis-lead\n${apk.sha256}\n${owner.descriptor}\n${JsonFiles.encode(captures)}"),
                owner, profile.nameCapture?.let(captures::get), captures, matches) }
        }.sortedBy { it.key }

    override fun drafts(profile: AnalysisProfile, leads: List<DiscoveryLead>): List<AnalysisRuleItem> = leads.filter { lead -> lead.matches.any { it.status == MatchStatus.PASS } }.mapNotNull { lead ->
        profile.locatorTemplate?.let { template -> AnalysisRuleItem(key = lead.key, proposedName = lead.suggestedName,
            locators = listOf(RuleEngine.instantiate(template, lead.captures)), discoveryKey = lead.key) }
            ?: profile.strategyTemplate?.let { template ->
                val params = template.parameters.deepCopy()
                profile.parameterCaptures.forEach { (parameter, capture) -> params.addProperty(parameter,
                    lead.captures[capture] ?: throw ValidationException("Missing discovery capture $capture")) }
                AnalysisRuleItem(key = lead.key, proposedName = lead.suggestedName, discoveryKey = lead.key, strategy = template.copy(parameters = params))
            }
    }
}
