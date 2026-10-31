package dev.dexlineage.messages

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import java.nio.file.Path

/** Messages-owned catalogue facts; kept byte-compatible with the schema-4 legacy RPC fields. */
data class RpcCallObservation(val source: MethodRef, val codeUnitOffset: Int, val service: String?, val rpc: String?,
    val status: String, val requestTypes: List<ClassRef> = emptyList(), val responseTypes: List<ClassRef> = emptyList(),
    val diagnostics: List<String> = emptyList())

data class RpcUnresolvedPath(val source: MethodRef, val codeUnitOffset: Int?, val reason: String,
    val service: String? = null, val rpc: String? = null, val role: String? = null) {
    fun uncertainty() = MatchUncertainty(source, codeUnitOffset, reason)
}

data class MessagesRpcCatalogue(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = MessagesRpcArtifacts.KIND,
    val apkSha256: String, val nameFactory: MethodRef, val calls: List<RpcCallObservation>,
    val unresolvedPaths: List<RpcUnresolvedPath>)

/** The method owner decodes this artifact. Matching orchestration never switches on its contents. */
object MessagesRpcArtifacts {
    const val KIND = "messages.rpc-catalogue"

    fun read(refs: List<ScenarioArtifactRef>): MessagesRpcCatalogue? {
        val selected = refs.filter { it.kind == KIND }.distinctBy { it.sha256 }
        if (selected.isEmpty()) return null
        requireInput(selected.size == 1, "Expected one Messages RPC catalogue for this analysis method")
        val ref = selected.single()
        Digests.verify(Artifact(ref.path, ref.sha256))
        val value = JsonFiles.read(Path.of(ref.path), MessagesRpcCatalogue::class.java)
        requireInput(value.kind == KIND && value.nameFactory.owner.apkSha256 == value.apkSha256, "Invalid Messages RPC catalogue identity")
        value.calls.forEach { call ->
            RuleProofsCompat.method(call.source, value.apkSha256)
            requireInput(call.codeUnitOffset >= 0 && call.status in setOf("RESOLVED", "NON_CONSTRUCTION", "UNRESOLVED_CONSTRUCTION"), "Invalid Messages RPC call observation")
            requireInput((call.requestTypes + call.responseTypes).all { it.apkSha256 == value.apkSha256 }, "RPC catalogue contains another APK")
        }
        value.unresolvedPaths.forEach { path ->
            RuleProofsCompat.method(path.source, value.apkSha256)
            requireInput(path.codeUnitOffset == null || path.codeUnitOffset >= 0, "Invalid RPC unresolved location")
            requireInput(path.role == null || path.role in setOf("request", "response"), "Invalid RPC unresolved role")
        }
        return value
    }

    private object RuleProofsCompat {
        fun method(method: MethodRef, apkSha256: String) {
            dev.dexlineage.knowledge.RuleProofs.validateEntity(EntityRef(method.owner, method))
            requireInput(method.owner.apkSha256 == apkSha256, "RPC observation belongs to another APK")
        }
    }
}
