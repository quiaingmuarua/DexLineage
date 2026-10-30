package dev.dexlineage.analysis

import com.google.gson.JsonObject
import dev.dexlineage.io.*
import dev.dexlineage.model.*

data class RpcRelation(val service: String, val rpc: String, val role: String)

/** RPC-specific drafting policy; raw construction and candidate truth stay in the APK adapter. */
internal object RpcAnalysis {
    fun validate(profile: AnalysisProfile) {
        val options = profile.rpcDrafts ?: return
        requireInput(profile.strategy?.strategyId == "grpc-java.rpc-discovery", "rpcDrafts requires grpc-java.rpc-discovery")
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
        val options = profile.rpcDrafts ?: RpcDraftOptions()
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
        if (profile.rpcDrafts == null) return emptyList()
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

    fun catalog(discovery: AnalysisDiscovery, calls: List<RpcCallObservation> = discovery.rpcCalls.orEmpty(),
                tasks: List<AnalysisTask> = emptyList(), decisions: List<AnalysisDecision> = emptyList()): Map<String, Any> {
        val reviewServices = discovery.profile.rpcDrafts?.reviewServices.orEmpty()
        val constructions = calls.filter { it.status != "NON_CONSTRUCTION" }
        val allRelations = constructions.filter { it.service != null && it.rpc != null }
            .flatMap { call -> listOf("request", "response").map { RpcRelation(call.service!!, call.rpc!!, it) } }
            .distinct().sortedWith(compareBy({ it.service }, { it.rpc }, { it.role }))
        val decisionsById = decisions.associateBy { it.taskId }
        val rows = allRelations.map { relation ->
            val observed = constructions.filter { it.service == relation.service && it.rpc == relation.rpc }
            val types = observed.flatMap { if (relation.role == "request") it.requestTypes else it.responseTypes }.distinct().sortedBy { it.descriptor }
            val matchingTasks = tasks.filter { relation in selectors(it.rule) }
            linkedMapOf<String, Any>("service" to relation.service, "rpc" to relation.rpc, "role" to relation.role,
                "inReviewScope" to (reviewServices.isEmpty() || relation.service in reviewServices), "types" to types,
                "constructionStatuses" to observed.map { it.status }.distinct().sorted(),
                "tasks" to matchingTasks.map { task -> linkedMapOf<String, Any>("taskId" to task.taskId,
                    "resolution" to (task.resolution?.status?.name ?: "WAITING_DEPENDENCY"),
                    "state" to (decisionsById[task.taskId]?.state?.name ?: "UNREVIEWED"),
                    "reason" to (decisionsById[task.taskId]?.reason ?: task.invalidReason ?: "review_missing")) })
        }
        return linkedMapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "analysis-rpc-catalog", "discoveryId" to discovery.discoveryId,
            "apk" to discovery.apk, "reviewServices" to reviewServices, "calls" to calls, "roles" to rows,
            "counts" to linkedMapOf("callSites" to calls.size, "callerMethods" to calls.map { it.source }.distinct().size,
                "capturedServices" to calls.mapNotNull { it.service }.distinct().size,
                "services" to constructions.mapNotNull { it.service }.distinct().size,
                "capturedServiceRpcPairs" to calls.filter { it.service != null && it.rpc != null }.map { it.service to it.rpc }.distinct().size,
                "serviceRpcPairs" to constructions.filter { it.service != null && it.rpc != null }.map { it.service to it.rpc }.distinct().size,
                "protoClasses" to constructions.flatMap { it.requestTypes + it.responseTypes }.distinct().size,
                "statuses" to calls.groupingBy { it.status }.eachCount().toSortedMap()))
    }
}
