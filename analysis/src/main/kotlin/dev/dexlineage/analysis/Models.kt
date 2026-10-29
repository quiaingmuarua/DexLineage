package dev.dexlineage.analysis

import dev.dexlineage.io.Digests
import dev.dexlineage.io.JsonFiles
import dev.dexlineage.model.*

data class AnalysisProfile(val schemaVersion: Int = SCHEMA_VERSION, val id: String = "",
    val discovery: Locator = Locator(), val nameCapture: String? = null,
    val locatorTemplate: LocatorTemplate? = null, val minConfidence: Confidence = Confidence.HIGH)
data class DiscoveryLead(val key: String, val owner: ClassRef, val suggestedName: String?,
    val captures: Map<String, String>, val matches: List<MatchFact>)
data class AnalysisDiscovery(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-discovery",
    val discoveryId: String, val engineBuildId: String, val toolVersion: String = TOOL_VERSION, val jadxVersion: String = JADX_VERSION,
    val apk: Artifact, val profileSource: Artifact, val profile: AnalysisProfile,
    val classInventory: Map<String, String>, val leads: List<DiscoveryLead>, val matches: List<MatchFact>, val scan: ScanStats,
    val matchCounts: Map<String, Int>, val conditionCounts: Map<String, Int>, val analysisDiagnostics: List<String>,
    val analysisMillis: Long, val createdAt: String) {
    fun fingerprint(): String = Digests.text(JsonFiles.encode(copy(discoveryId = "", createdAt = "",
        scan = scan.copy(elapsedMillis = 0), analysisMillis = 0)))
}
data class AnalysisDiscoveryResult(val schemaVersion: Int = SCHEMA_VERSION, val discoveryId: String,
    val leads: Int, val draftedRules: Int, val discoveryPath: String, val rulesPath: String?,
    val evidence: List<EvidenceRecord>, val scan: ScanStats, val analysisMillis: Long)
data class AnalysisRuleItem(val key: String = "", val semanticId: String? = null, val proposedName: String? = null,
    val locators: List<Locator> = emptyList(), val discoveryKey: String? = null)
data class AnalysisRuleFile(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-rules",
    val discovery: Artifact? = null, val minConfidence: Confidence = Confidence.HIGH,
    val items: List<AnalysisRuleItem> = emptyList())
data class AnalysisTask(val taskId: String, val request: AnalysisRuleItem, val rule: RuleRevision,
    val resolution: Resolution, val expectedOwner: ClassRef?, val existingEntry: KnowledgeEntry?,
    val semanticId: String?, val invalidReason: String?)
data class AnalysisRun(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-run",
    val runId: String, val engineBuildId: String, val toolVersion: String = TOOL_VERSION, val jadxVersion: String = JADX_VERSION,
    val apk: Artifact, val rulesFile: Artifact, val rules: AnalysisRuleFile,
    val discoveryFile: Artifact?, val discovery: AnalysisDiscovery?, val baseFile: Artifact?, val baseKnowledge: VersionKnowledge?,
    val classInventory: Map<String, String>, val tasks: List<AnalysisTask>, val scan: ScanStats,
    val analysisDiagnostics: List<String>, val analysisMillis: Long, val createdAt: String) {
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
    val offset: Int, val limit: Int, val counts: Map<String, Int>, val items: List<AnalysisTaskView>, val carriedUnresolved: List<UnresolvedKnowledge>)
data class AnalysisSubmitResult(val schemaVersion: Int = SCHEMA_VERSION, val runId: String,
    val revisions: Map<String, String>, val counts: Map<String, Int>)
data class AnalysisPublishResult(val schemaVersion: Int = SCHEMA_VERSION, val runId: String, val knowledgeId: String,
    val acceptedUpdates: Int, val confirmed: Int, val unresolved: Int, val counts: Map<String, Int>,
    val knowledgePath: String, val mappingPath: String, val reportPath: String)
