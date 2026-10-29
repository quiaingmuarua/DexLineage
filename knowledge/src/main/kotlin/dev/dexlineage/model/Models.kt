package dev.dexlineage.model

const val SCHEMA_VERSION = 3
const val TOOL_VERSION = "0.3.0"
const val JADX_VERSION = "1.5.0"

data class Artifact(val path: String, val sha256: String)
data class ClassRef(val apkSha256: String, val descriptor: String, val dexEntry: String)
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
    val field: FieldBinding? = null, val stringUses: List<StringUseSite> = emptyList(), val locatorIndex: Int = 0)
data class FieldAnalysis(val bindings: List<FieldBinding>, val code: List<DecompiledClass>, val diagnostics: List<String>, val elapsedMillis: Long,
    val unavailableOwners: Set<String> = emptySet())
data class QueryResult(val matches: List<MatchFact>, val scan: ScanResult, val analysis: FieldAnalysis?)

data class RuleRevision(val revisionId: String = "", val locators: List<Locator> = emptyList())
enum class ResolutionStatus { UNIQUE, NO_MATCH, AMBIGUOUS, UNKNOWN }
data class ResolutionCandidate(val ref: ClassRef, val status: MatchStatus, val matches: List<MatchFact>)
data class Resolution(val schemaVersion: Int = SCHEMA_VERSION, val resolutionId: String,
    val apkSha256: String, val rule: RuleRevision, val engineVersion: String = TOOL_VERSION,
    val engineBuildId: String, val searchScope: String = "apk-all-dex",
    val status: ResolutionStatus, val candidates: List<ResolutionCandidate>, val matches: List<MatchFact>) {
    val uniqueRef: ClassRef? get() = if (status == ResolutionStatus.UNIQUE) candidates.single().ref else null
}
data class ResolutionBatch(val resolutions: Map<String, Resolution>, val scan: ScanResult, val analysis: FieldAnalysis?)

data class KnowledgeEvidence(val evidenceId: String, val ref: ClassRef, val javaPath: String, val javaSha256: String,
    val smaliPath: String?, val smaliSha256: String?, val incomplete: Boolean, val diagnostics: List<String>)
data class KnowledgeEntry(val semanticId: String, val name: String, val binding: ClassRef, val captures: Map<String, String>,
    val locators: List<Locator>, val evidence: List<KnowledgeEvidence>, val rationale: String, val provenance: String,
    val ruleRevision: RuleRevision? = null, val resolution: Resolution? = null)
/** Last confirmed knowledge, never a guessed binding to the current APK. */
data class UnresolvedKnowledge(val entry: KnowledgeEntry, val sourceKnowledgeId: String, val reason: String, val originRun: String)
data class VersionKnowledge(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "version-knowledge", val knowledgeId: String,
    val artifact: Artifact, val entries: List<KnowledgeEntry>, val unresolved: List<UnresolvedKnowledge>, val provenance: String,
    val parentKnowledgeId: String? = null)

/** Mechanical journal only; scenario owners interpret payloads and decide state. */
data class StoredReview(val schemaVersion: Int = SCHEMA_VERSION, val revisionId: String, val runId: String, val taskId: String,
    val supersedes: String?, val payload: com.google.gson.JsonObject)
data class ReviewRequest(val taskId: String, val supersedes: String?, val payload: Any)
data class ReviewTransaction(val schemaVersion: Int = SCHEMA_VERSION, val transactionId: String, val runId: String, val records: List<StoredReview>)
