package dev.dexlineage.analysis

import dev.dexlineage.io.Digests
import dev.dexlineage.io.JsonFiles
import dev.dexlineage.model.*
import com.google.gson.JsonObject
import com.google.gson.annotations.JsonAdapter

@JsonAdapter(AnalysisCompatibilityCodec::class)
data class AnalysisProfile(val schemaVersion: Int = SCHEMA_VERSION, val id: String = "",
    val discovery: Locator = Locator(), val nameCapture: String? = null,
    val locatorTemplate: LocatorTemplate? = null, val minConfidence: Confidence = Confidence.HIGH,
    val strategy: StrategySpec? = null, val strategyTemplate: StrategySpec? = null,
    val parameterCaptures: Map<String, String> = emptyMap(), val method: AnalysisMethodSpec? = null,
    @Transient val compatibility: JsonObject? = null)

data class AnalysisMethodSpec(val methodId: String = "profile", val parameters: JsonObject = JsonObject())
data class DiscoveryLead(val key: String, val owner: ClassRef, val suggestedName: String?,
    val captures: Map<String, String>, val matches: List<MatchFact>)
@JsonAdapter(AnalysisCompatibilityCodec::class)
data class AnalysisDiscovery(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-discovery",
    val discoveryId: String, val engineBuildId: String, val toolVersion: String = TOOL_VERSION, val jadxVersion: String = JADX_VERSION,
    val apk: Artifact, val profileSource: Artifact, val profile: AnalysisProfile,
    val classInventory: Map<String, String>, val leads: List<DiscoveryLead>, val matches: List<MatchFact>, val scan: ScanStats,
    val matchCounts: Map<String, Int>, val conditionCounts: Map<String, Int>, val analysisDiagnostics: List<String>,
    val analysisMillis: Long, val createdAt: String,
    val baseFile: Artifact? = null, val baseKnowledge: VersionKnowledge? = null,
    val unresolvedPaths: List<UnresolvedPath>? = null,
    val methodArtifacts: List<ScenarioArtifactRef>? = null, @Transient val compatibility: JsonObject? = null) {
    fun fingerprint(): String = Digests.text(JsonFiles.encode(copy(discoveryId = "", createdAt = "",
        scan = scan.copy(elapsedMillis = 0), analysisMillis = 0)))
}
data class AnalysisDiscoveryResult(val schemaVersion: Int = SCHEMA_VERSION, val discoveryId: String,
    val leads: Int, val draftedRules: Int, val discoveryPath: String, val rulesPath: String?,
    val evidence: List<EvidenceRecord>, val scan: ScanStats, val analysisMillis: Long,
    val artifacts: List<ScenarioArtifactRef> = emptyList())
data class AnalysisRuleItem(val key: String = "", val semanticId: String? = null, val proposedName: String? = null,
    val locators: List<Locator> = emptyList(), val discoveryKey: String? = null,
    val strategy: StrategySpec? = null, val corpusTargetId: String? = null)
data class AnalysisAnchorDefinition(val key: String = "", val locators: List<Locator> = emptyList(), val strategy: StrategySpec? = null)
data class AnalysisRuleFile(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-rules",
    val discovery: Artifact? = null, val minConfidence: Confidence = Confidence.HIGH,
    val items: List<AnalysisRuleItem> = emptyList(), val anchors: List<AnalysisAnchorDefinition> = emptyList())
enum class AnalysisExecutionState { EXECUTED, WAITING_DEPENDENCY, INHERITED }
data class AnalysisTask(val taskId: String, val request: AnalysisRuleItem, val rule: RuleRevision,
    val resolution: Resolution?, val expectedOwner: ClassRef?, val existingEntry: KnowledgeEntry?,
    val semanticId: String?, val invalidReason: String?,
    val executionState: AnalysisExecutionState = AnalysisExecutionState.EXECUTED, val waitingFor: List<String> = emptyList(),
    val identitySourceKnowledgeId: String? = null)

/** Identity reference only: its old matching/review never authorizes a new binding. */
data class IdentityReference(val file: Artifact, val knowledge: VersionKnowledge, val mappingFile: Artifact, val reportFile: Artifact)
data class AnalysisAnchorTask(val key: String, val rule: RuleRevision, val resolution: Resolution?,
    val executionState: AnalysisExecutionState, val waitingFor: List<String> = emptyList())
@JsonAdapter(AnalysisCompatibilityCodec::class)
data class AnalysisRun(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-run",
    val runId: String, val engineBuildId: String, val toolVersion: String = TOOL_VERSION, val jadxVersion: String = JADX_VERSION,
    val apk: Artifact, val rulesFile: Artifact, val rules: AnalysisRuleFile,
    val discoveryFile: Artifact?, val discovery: AnalysisDiscovery?, val baseFile: Artifact?, val baseKnowledge: VersionKnowledge?,
    val classInventory: Map<String, String>, val tasks: List<AnalysisTask>, val scan: ScanStats,
    val analysisDiagnostics: List<String>, val analysisMillis: Long, val createdAt: String,
    val anchorTasks: List<AnalysisAnchorTask> = emptyList(), val corpusFile: Artifact? = null, val corpus: ManualCorpus? = null,
    val identityReferences: List<IdentityReference>? = null, val methodArtifacts: List<ScenarioArtifactRef>? = null,
    @Transient val compatibility: JsonObject? = null) {
    fun fingerprint(): String = Digests.text(JsonFiles.encode(copy(runId = "", createdAt = "", scan = scan.copy(elapsedMillis = 0),
        analysisMillis = 0, discovery = discovery?.copy(createdAt = "", scan = discovery.scan.copy(elapsedMillis = 0), analysisMillis = 0))))
}
data class AnalysisReview(val taskId: String = "", val resolutionId: String = "", val ruleRevisionId: String = "",
    val action: ReviewAction = ReviewAction.DEFER, val name: String? = null, val level: Confidence = Confidence.LOW,
    val rationale: String = "", val unverified: List<String> = emptyList(), val evidenceIds: List<String> = emptyList(), val supersedes: String? = null)
data class AnalysisReviewBatch(val schemaVersion: Int = SCHEMA_VERSION, val runId: String = "", val apkSha256: String = "",
    val items: List<AnalysisReview> = emptyList())
data class AnalysisDecision(val taskId: String, val state: TaskState, val reason: String, val semanticId: String?,
    val target: ClassRef?, val name: String?, val review: AnalysisReview?)
data class AnalysisTaskView(val task: AnalysisTask, val state: TaskState, val reason: String, val latestRevision: String?)
data class AnalysisTaskPage(val schemaVersion: Int = SCHEMA_VERSION, val runId: String, val total: Int,
    val offset: Int, val limit: Int, val counts: Map<String, Int>, val items: List<AnalysisTaskView>, val carriedUnresolved: List<UnresolvedKnowledge>,
    val anchors: List<AnalysisAnchorTask> = emptyList())
data class AnalysisSubmitResult(val schemaVersion: Int = SCHEMA_VERSION, val runId: String,
    val revisions: Map<String, String>, val counts: Map<String, Int>)
data class AnalysisPublishResult(val schemaVersion: Int = SCHEMA_VERSION, val runId: String, val knowledgeId: String,
    val acceptedUpdates: Int, val confirmed: Int, val unresolved: Int, val counts: Map<String, Int>,
    val knowledgePath: String, val mappingPath: String, val reportPath: String, val anchors: Int = 0)

data class ManualAnnotation(val kind: String, val ownerDescriptor: String, val memberId: String?,
    val name: String, val codeRef: JsonObject?, val original: JsonObject)
data class ManualTarget(val targetId: String, val source: ClassRef, val manualName: String, val annotationIndex: Int)
data class ManualCorpus(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "manual-corpus",
    val corpusId: String, val apk: Artifact, val project: Artifact, val projectVersion: Int,
    val annotations: List<ManualAnnotation>, val targets: List<ManualTarget>, val annotationCounts: Map<String, Int>) {
    fun fingerprint(): String = Digests.text(JsonFiles.encode(copy(corpusId = "")))
}
data class CorpusTargetView(val target: ManualTarget, val state: String, val reason: String?,
    val taskId: String?, val resolution: Resolution?, val confirmedEntry: KnowledgeEntry?)
data class CorpusTargetPage(val schemaVersion: Int = SCHEMA_VERSION, val corpusId: String, val runId: String?,
    val total: Int, val offset: Int, val limit: Int, val counts: Map<String, Int>, val items: List<CorpusTargetView>,
    val additionalTasks: List<String> = emptyList())
