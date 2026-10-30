package dev.dexlineage.model

const val SCHEMA_VERSION = 4
const val TOOL_VERSION = "0.4.0"
const val JADX_VERSION = "1.5.0"

data class Artifact(val path: String, val sha256: String)
data class ClassRef(val apkSha256: String, val descriptor: String, val dexEntry: String)
enum class EntityKind { CLASS, METHOD }
data class MethodRef(val owner: ClassRef, val name: String, val descriptor: String)
data class EntityRef(val owner: ClassRef, val method: MethodRef? = null) {
    val kind: EntityKind get() = if (method == null) EntityKind.CLASS else EntityKind.METHOD
    val identity: String get() = owner.descriptor + (method?.let { "->${it.name}${it.descriptor}" } ?: "")
}
data class StringUseSite(val dexEntry: String, val classDescriptor: String, val methodDescriptor: String, val codeUnitOffset: Int, val fileOffset: Int, val literal: String)
data class ScanStats(val classCount: Int, val methodCount: Long, val instructionCount: Long, val stringUseSites: Long, val elapsedMillis: Long, val diagnostics: List<String>)
data class ScanResult(val classes: Map<String, String>, val uses: Map<String, List<StringUseSite>>, val stats: ScanStats)
data class DecompiledClass(val descriptor: String, val javaCode: String, val smaliCode: String?, val incomplete: Boolean, val diagnostics: List<String>, val elapsedMillis: Long)
data class EvidenceRecord(val schemaVersion: Int = SCHEMA_VERSION, val evidenceId: String, val runId: String, val ref: ClassRef,
    val javaPath: String, val javaSha256: String, val smaliPath: String?, val smaliSha256: String?,
    val incomplete: Boolean, val diagnostics: List<String>, val elapsedMillis: Long)
enum class Confidence { HIGH, MEDIUM, LOW }
enum class ReviewAction { ACCEPT, REJECT, DEFER }
enum class TaskState { UNREVIEWED, ACCEPTED, REJECTED, DEFERRED, INVALID }
data class AcceptedRename(val descriptor: String, val newFullName: String)
data class VerifiedRename(val descriptor: String, val rawName: String, val displayedName: String)

/** Data-only predicates; unsupported kinds must never silently pass. */
data class FactorSpec(val kind: String = "", val requiredFlags: List<String> = emptyList(), val visibility: String? = null,
    val invocationKind: String? = null, val parameterTypes: List<String>? = null, val returnType: String? = null,
    val returnSameAsField: Boolean = false, val index: Int? = null, val value: String? = null,
    val valueFromCapture: String? = null)
data class CaptureSpec(val name: String = "", val argumentIndex: Int = -1)
data class Locator(val kind: String = "", val anchor: String = "", val factors: List<FactorSpec> = emptyList(), val captures: List<CaptureSpec> = emptyList())
data class LocatorTemplate(val kind: String = "", val anchorFromCapture: String = "", val factors: List<FactorSpec> = emptyList(), val captures: List<CaptureSpec> = emptyList())
enum class MatchStatus { PASS, FAIL, UNKNOWN }
data class FactorResult(val kind: String, val status: MatchStatus, val detail: String)
data class CallFact(val declaringType: String, val methodName: String, val parameterTypes: List<String>, val returnType: String,
    val invocationKind: String, val arguments: List<String?>, val codeUnitOffset: Int?, val knownNonStringArguments: Set<Int> = emptySet())
data class FieldBinding(val owner: ClassRef, val fieldName: String, val fieldType: String, val accessFlags: Int,
    val initializerMethod: String?, val call: CallFact?, val assignmentOwner: String?, val unknownReason: String? = null)
data class MatchFact(val owner: ClassRef, val status: MatchStatus, val factors: List<FactorResult>, val captures: Map<String, String>,
    val field: FieldBinding? = null, val stringUses: List<StringUseSite> = emptyList(), val locatorIndex: Int = 0,
    val method: MethodRef? = null, val relatedRefs: List<ClassRef> = emptyList(), val trace: List<FactTrace> = emptyList())
data class FactTrace(val owner: ClassRef, val methodDescriptor: String?, val codeUnitOffset: Int?, val kind: String, val detail: String)
data class FieldAnalysis(val bindings: List<FieldBinding>, val code: List<DecompiledClass>, val diagnostics: List<String>, val elapsedMillis: Long,
    val unavailableOwners: Set<String> = emptySet())
/** An unresolved construction path has a source location but need not have a defensible entity candidate. */
data class UnresolvedPath(val source: MethodRef, val codeUnitOffset: Int?, val reason: String,
    val service: String? = null, val rpc: String? = null, val role: String? = null)

/** Raw invocation catalogue for discovery; no name or publication authority. */
data class RpcCallObservation(val source: MethodRef, val codeUnitOffset: Int, val service: String?, val rpc: String?,
    val status: String, val requestTypes: List<ClassRef> = emptyList(), val responseTypes: List<ClassRef> = emptyList(),
    val diagnostics: List<String> = emptyList())

data class QueryResult(val matches: List<MatchFact>, val scan: ScanResult, val analysis: FieldAnalysis?,
    val rpcCalls: List<RpcCallObservation>? = null, val unresolvedPaths: List<UnresolvedPath>? = null)

data class StrategySpec(val strategyId: String = "", val parameters: com.google.gson.JsonObject = com.google.gson.JsonObject(),
    val resultKind: EntityKind = EntityKind.CLASS, val requires: Map<String, String> = emptyMap())
data class RuleRevision(val revisionId: String = "", val locators: List<Locator> = emptyList(),
    val strategyId: String = "builtin.locators", val parameters: com.google.gson.JsonObject = com.google.gson.JsonObject(),
    val resultKind: EntityKind = EntityKind.CLASS, val requires: Map<String, String> = emptyMap())
enum class ResolutionStatus { UNIQUE, NO_MATCH, AMBIGUOUS, UNKNOWN }
data class ResolutionCandidate(val ref: ClassRef, val status: MatchStatus, val matches: List<MatchFact>, val method: MethodRef? = null) {
    val entity: EntityRef get() = EntityRef(ref, method)
}
data class Resolution(val schemaVersion: Int = SCHEMA_VERSION, val resolutionId: String,
    val apkSha256: String, val rule: RuleRevision, val engineVersion: String = TOOL_VERSION,
    val engineBuildId: String, val searchScope: String = "apk-all-dex",
    val status: ResolutionStatus, val candidates: List<ResolutionCandidate>, val matches: List<MatchFact>,
    val dependencies: Map<String, SupportAnchor> = emptyMap(), val unresolvedPaths: List<UnresolvedPath>? = null) {
    val uniqueEntity: EntityRef? get() = if (status == ResolutionStatus.UNIQUE) candidates.single().entity else null
    val uniqueRef: ClassRef? get() = uniqueEntity?.takeIf { it.kind == EntityKind.CLASS }?.owner
    val uniqueMethod: MethodRef? get() = uniqueEntity?.method
}
data class ResolutionBatch(val resolutions: Map<String, Resolution>, val scan: ScanResult, val analysis: FieldAnalysis?,
    val waiting: Map<String, List<String>> = emptyMap(), val rpcCalls: List<RpcCallObservation>? = null)

data class KnowledgeEvidence(val evidenceId: String, val ref: ClassRef, val javaPath: String, val javaSha256: String,
    val smaliPath: String?, val smaliSha256: String?, val incomplete: Boolean, val diagnostics: List<String>)
data class KnowledgeEntry(val semanticId: String, val name: String, val binding: ClassRef, val captures: Map<String, String>,
    val locators: List<Locator>, val evidence: List<KnowledgeEvidence>, val rationale: String, val provenance: String,
    val ruleRevision: RuleRevision? = null, val resolution: Resolution? = null)
data class SupportAnchor(val key: String, val binding: EntityRef, val rule: RuleRevision, val resolution: Resolution,
    val evidence: List<KnowledgeEvidence> = emptyList())
/** Last confirmed knowledge, never a guessed binding to the current APK. */
data class UnresolvedKnowledge(val entry: KnowledgeEntry, val sourceKnowledgeId: String, val reason: String, val originRun: String)
data class VersionKnowledge(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "version-knowledge", val knowledgeId: String,
    val artifact: Artifact, val entries: List<KnowledgeEntry>, val unresolved: List<UnresolvedKnowledge>, val provenance: String,
    val parentKnowledgeId: String? = null, val anchors: List<SupportAnchor> = emptyList(),
    val migrationSourceKnowledgeId: String? = null)

/** Mechanical journal only; scenario owners interpret payloads and decide state. */
data class StoredReview(val schemaVersion: Int = SCHEMA_VERSION, val revisionId: String, val runId: String, val taskId: String,
    val supersedes: String?, val payload: com.google.gson.JsonObject)
data class ReviewRequest(val taskId: String, val supersedes: String?, val payload: Any)
data class ReviewTransaction(val schemaVersion: Int = SCHEMA_VERSION, val transactionId: String, val runId: String, val records: List<StoredReview>)
