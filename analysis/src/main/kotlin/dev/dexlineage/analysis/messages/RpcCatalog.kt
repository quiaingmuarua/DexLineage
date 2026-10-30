package dev.dexlineage.analysis.messages

import dev.dexlineage.messages.RpcCallObservation
import dev.dexlineage.model.*

/** Scenario-owned projection. Field order preserves the original schema-4 catalogue encoding. */
data class RpcCatalog(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-rpc-catalog",
    val discoveryId: String, val apk: Artifact, val reviewServices: List<String>, val calls: List<RpcCallObservation>,
    val roles: List<RpcRole>, val counts: RpcCounts)
data class RpcRole(val service: String, val rpc: String, val role: String, val inReviewScope: Boolean,
    val types: List<ClassRef>, val constructionStatuses: List<String>, val tasks: List<RpcTaskRow>)
data class RpcTaskRow(val taskId: String, val resolution: String, val state: String, val reason: String)
data class RpcCounts(val callSites: Int, val callerMethods: Int, val capturedServices: Int, val services: Int,
    val capturedServiceRpcPairs: Int, val serviceRpcPairs: Int, val protoClasses: Int, val statuses: Map<String, Int>)
