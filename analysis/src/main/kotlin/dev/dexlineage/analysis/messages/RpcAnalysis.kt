package dev.dexlineage.analysis.messages

import dev.dexlineage.analysis.*

import com.google.gson.JsonObject
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import dev.dexlineage.messages.MessagesRpcArtifacts
import dev.dexlineage.messages.RpcCallObservation
import java.nio.file.Path

data class RpcDraftOptions(val reviewServices: List<String> = emptyList(), val requestSuffix: String = "Request", val responseSuffix: String = "Response")

data class RpcRelation(val service: String, val rpc: String, val role: String)

/** RPC-specific drafting policy; raw construction and candidate truth stay in the APK adapter. */
internal object RpcAnalysis {
    fun options(profile: AnalysisProfile): RpcDraftOptions {
        val params = profile.method?.parameters ?: JsonObject()
        requireInput(params.keySet().all { it in setOf("reviewServices", "requestSuffix", "responseSuffix") }, "Unknown Messages gRPC method option")
        return JsonFiles.gson.fromJson(params, RpcDraftOptions::class.java)
    }

    fun calls(refs: List<ScenarioArtifactRef>?, legacy: JsonObject? = null): List<RpcCallObservation> =
        legacy?.getAsJsonArray("rpcCalls")?.map { JsonFiles.gson.fromJson(it, RpcCallObservation::class.java) }
            ?: MessagesRpcArtifacts.read(refs.orEmpty())?.calls.orEmpty()

    fun validate(profile: AnalysisProfile) {
        val options = options(profile)
        requireInput(profile.strategy?.strategyId == "grpc-java.rpc-discovery", "Messages gRPC analysis requires grpc-java.rpc-discovery")
        requireInput(profile.locatorTemplate == null && profile.strategyTemplate == null && profile.nameCapture == null && profile.parameterCaptures.isEmpty(),
            "RPC drafts own grouping and naming; do not combine them with generic capture templates")
        requireInput(options.reviewServices.all { it.isNotBlank() } && options.reviewServices.distinct().size == options.reviewServices.size,
            "RPC review services must be distinct nonempty exact names")
        listOf(options.requestSuffix, options.responseSuffix).forEach {
            requireInput(it.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")), "RPC name suffix must be an identifier fragment")
        }
    }

    private fun relation(fact: MatchFact): RpcRelation? {
        val service = fact.captures["service"] ?: return null
        val rpc = fact.captures["rpc"] ?: return null
        val role = fact.captures["role"]?.takeIf { it in setOf("request", "response") } ?: return null
        return RpcRelation(service, rpc, role)
    }

    fun relations(facts: List<MatchFact>): List<RpcRelation> = facts.mapNotNull(::relation).distinct()
        .sortedWith(compareBy({ it.service }, { it.rpc }, { it.role }))

    fun leads(apk: Artifact, profile: AnalysisProfile, matches: List<MatchFact>): List<DiscoveryLead> {
        val options = options(profile)
        return matches.filter { it.status != MatchStatus.FAIL }.groupBy { it.owner }.map { (owner, facts) ->
            val names = relations(facts.filter { it.status == MatchStatus.PASS }).map {
                it.rpc + if (it.role == "request") options.requestSuffix else options.responseSuffix
            }.distinct()
            // Captures remain values actually present at call sites. A proposed name is separate.
            val common = facts.first().captures.filter { (key, value) -> facts.all { it.captures[key] == value } }.toSortedMap()
            DiscoveryLead(Digests.text("analysis-rpc-lead\n${apk.sha256}\n${owner.dexEntry}\n${owner.descriptor}"),
                owner, names.singleOrNull(), common, facts)
        }.sortedBy { it.key }
    }

    fun drafts(profile: AnalysisProfile, leads: List<DiscoveryLead>): List<AnalysisRuleItem> {
        return leads.filter { lead -> lead.matches.any { it.status == MatchStatus.PASS } }.map { lead ->
            val relations = relations(lead.matches)
            requireInput(relations.isNotEmpty(), "RPC Proto facts lack service/RPC/role captures")
            val params = JsonObject()
            listOf("requestLabel", "responseLabel", "nameLabel").forEach { name ->
                profile.strategy!!.parameters.get(name)?.let { params.add(name, it.deepCopy()) }
            }
            params.add("selectors", JsonFiles.gson.toJsonTree(relations))
            AnalysisRuleItem(lead.key, proposedName = lead.suggestedName, discoveryKey = lead.key,
                strategy = StrategySpec("grpc-java.rpc-message", params, EntityKind.CLASS, profile.strategy!!.requires))
        }
    }

    fun selectors(rule: RuleRevision): List<RpcRelation> {
        if (rule.strategyId == "grpc-java.rpc-message") return rule.parameters.getAsJsonArray("selectors").map {
            val p = it.asJsonObject
            RpcRelation(p.get("service").asString, p.get("rpc").asString, p.get("role").asString)
        }
        if (rule.strategyId == "messages.rpc-message") return listOf(RpcRelation(rule.parameters.get("service").asString,
            rule.parameters.get("rpc").asString, rule.parameters.get("role").asString))
        return emptyList()
    }

    fun matchesServices(task: AnalysisTask, services: Set<String>): Boolean =
        services.isEmpty() || selectors(task.rule).any { it.service in services }

    fun catalog(discovery: AnalysisDiscovery, calls: List<RpcCallObservation> = calls(discovery.methodArtifacts, discovery.compatibility),
                tasks: List<AnalysisTask> = emptyList(), decisions: List<AnalysisDecision> = emptyList()): RpcCatalog {
        val reviewServices = options(discovery.profile).reviewServices
        val constructions = calls.filter { it.status != "NON_CONSTRUCTION" }
        val allRelations = constructions.filter { it.service != null && it.rpc != null }
            .flatMap { call -> listOf("request", "response").map { RpcRelation(call.service!!, call.rpc!!, it) } }
            .distinct().sortedWith(compareBy({ it.service }, { it.rpc }, { it.role }))
        val decisionsById = decisions.associateBy { it.taskId }
        val rows = allRelations.map { relation ->
            val observed = constructions.filter { it.service == relation.service && it.rpc == relation.rpc }
            val types = observed.flatMap { if (relation.role == "request") it.requestTypes else it.responseTypes }.distinct().sortedBy { it.descriptor }
            val matchingTasks = tasks.filter { relation in selectors(it.rule) }
            RpcRole(relation.service, relation.rpc, relation.role,
                reviewServices.isEmpty() || relation.service in reviewServices, types,
                observed.map { it.status }.distinct().sorted(),
                matchingTasks.map { task -> RpcTaskRow(task.taskId,
                    task.resolution?.status?.name ?: "WAITING_DEPENDENCY",
                    decisionsById[task.taskId]?.state?.name ?: "UNREVIEWED",
                    decisionsById[task.taskId]?.reason ?: task.invalidReason ?: "review_missing") })
        }
        return RpcCatalog(discoveryId = discovery.discoveryId, apk = discovery.apk, reviewServices = reviewServices,
            calls = calls, roles = rows, counts = RpcCounts(calls.size, calls.map { it.source }.distinct().size,
                calls.mapNotNull { it.service }.distinct().size, constructions.mapNotNull { it.service }.distinct().size,
                calls.filter { it.service != null && it.rpc != null }.map { it.service to it.rpc }.distinct().size,
                constructions.filter { it.service != null && it.rpc != null }.map { it.service to it.rpc }.distinct().size,
                constructions.flatMap { it.requestTypes + it.responseTypes }.distinct().size,
                calls.groupingBy { it.status }.eachCount().toSortedMap()))
    }
}

/** Messages' finite analysis recipe; orchestration and acceptance remain in Analysis. */
internal object MessagesGrpcAnalysisMethod : AnalysisMethod {
    override val id = "messages.grpc"
    override val seedRounds = 3
    override fun validate(profile: AnalysisProfile) = RpcAnalysis.validate(profile)
    override fun leads(apk: Artifact, profile: AnalysisProfile, facts: List<MatchFact>) = RpcAnalysis.leads(apk, profile, facts)
    override fun drafts(profile: AnalysisProfile, leads: List<DiscoveryLead>) = RpcAnalysis.drafts(profile, leads)
    override fun selectedReviewTaskIds(run: AnalysisRun): Set<String> {
        val services = run.discovery?.profile?.let(RpcAnalysis::options)?.reviewServices.orEmpty().toSet()
        return run.tasks.filter { RpcAnalysis.matchesServices(it, services) }.map { it.taskId }.toSet()
    }
    override fun matches(task: AnalysisTask, filters: Map<String, Set<String>>): Boolean {
        requireInput(filters.keys.all { it == "service" }, "Unsupported Messages gRPC task filter")
        return RpcAnalysis.matchesServices(task, filters["service"].orEmpty())
    }
    override fun taskDetails(task: AnalysisTask): JsonObject = JsonObject().apply {
        add("relations", JsonFiles.gson.toJsonTree(RpcAnalysis.selectors(task.rule)))
    }
    override fun validateArtifacts(artifacts: List<ScenarioArtifactRef>, compatibility: JsonObject?, apk: Artifact, inventory: Map<String, String>) {
        MessagesRpcArtifacts.read(artifacts)?.let { catalogue ->
            requireInput(catalogue.apkSha256 == apk.sha256 && inventory[catalogue.nameFactory.owner.descriptor] == catalogue.nameFactory.owner.dexEntry,
                "Method catalogue belongs to another APK or name-factory DEX")
            catalogue.unresolvedPaths.forEach { path ->
                requireInput(path.source.owner.apkSha256 == apk.sha256 && inventory[path.source.owner.descriptor] == path.source.owner.dexEntry,
                    "Method catalogue contains an invalid unresolved source")
            }
        }
        RpcAnalysis.calls(artifacts, compatibility).forEach { call ->
            val refs = listOf(call.source.owner) + call.requestTypes + call.responseTypes
            requireInput(call.codeUnitOffset >= 0 && refs.all { it.apkSha256 == apk.sha256 && inventory[it.descriptor] == it.dexEntry },
                "Method catalogue contains an invalid source or Proto binding")
        }
    }
    override fun discoveryArtifacts(discovery: AnalysisDiscovery, out: Path): List<ScenarioArtifactRef> =
        writeCatalog(out, RpcAnalysis.catalog(discovery))
    override fun validateDiscoveryArtifacts(discovery: AnalysisDiscovery, out: Path): List<ScenarioArtifactRef> =
        validateCatalog(out, RpcAnalysis.catalog(discovery))
    override fun publicationArtifacts(run: AnalysisRun, decisions: List<AnalysisDecision>, out: Path): List<ScenarioArtifactRef> {
        val discovery = run.discovery ?: return emptyList()
        val calls = RpcAnalysis.calls(run.methodArtifacts, run.compatibility).ifEmpty { RpcAnalysis.calls(discovery.methodArtifacts, discovery.compatibility) }
        val copied = AnalysisMethods.copyArtifacts(run.methodArtifacts.orEmpty().ifEmpty { discovery.methodArtifacts.orEmpty() }, out).orEmpty()
        return copied + writeCatalog(out, RpcAnalysis.catalog(discovery, calls, run.tasks, decisions))
    }
    override fun validatePublicationArtifacts(run: AnalysisRun, decisions: List<AnalysisDecision>, out: Path): List<ScenarioArtifactRef> {
        val discovery = run.discovery ?: return emptyList()
        val calls = RpcAnalysis.calls(run.methodArtifacts, run.compatibility).ifEmpty { RpcAnalysis.calls(discovery.methodArtifacts, discovery.compatibility) }
        val copied = AnalysisMethods.validateCopiedArtifacts(run.methodArtifacts.orEmpty().ifEmpty { discovery.methodArtifacts.orEmpty() }, out)
        return copied + validateCatalog(out, RpcAnalysis.catalog(discovery, calls, run.tasks, decisions))
    }
    private fun writeCatalog(out: Path, content: RpcCatalog): List<ScenarioArtifactRef> {
        val path = out.resolve("rpc-catalog.json")
        JsonFiles.writeNew(path, content)
        return listOf(ScenarioArtifactRef("messages.grpc.catalog", path.toAbsolutePath().toString(), Digests.file(path)))
    }
    private fun validateCatalog(out: Path, expected: RpcCatalog): List<ScenarioArtifactRef> {
        val path = out.resolve("rpc-catalog.json")
        requireInput(JsonFiles.read(path, RpcCatalog::class.java) == expected, "Messages catalogue differs from frozen discovery and decisions")
        return listOf(ScenarioArtifactRef("messages.grpc.catalog", path.toAbsolutePath().toString(), Digests.file(path)))
    }
}
