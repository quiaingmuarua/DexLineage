package dev.dexlineage.migration

import dev.dexlineage.io.Digests
import dev.dexlineage.io.JsonFiles
import dev.dexlineage.model.*

data class MigrationRuleOverride(val semanticId: String = "", val locators: List<Locator> = emptyList(), val expectedRevision: String? = null)
data class MigrationRulesFile(val schemaVersion: Int = SCHEMA_VERSION, val items: List<MigrationRuleOverride> = emptyList())
data class MigrationTask(val taskId: String, val entry: KnowledgeEntry, val resolution: Resolution) {
    val candidates: List<ResolutionCandidate> get() = resolution.candidates
    val matches: List<MatchFact> get() = resolution.matches
}
data class MigrationRun(
    val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "migration-run", val runId: String,
    val toolVersion: String = TOOL_VERSION, val jadxVersion: String = JADX_VERSION,
    val knowledgeFile: Artifact, val knowledge: VersionKnowledge, val sourceApk: Artifact, val targetApk: Artifact,
    val minConfidence: Confidence, val tasks: List<MigrationTask>, val sourceInventory: Map<String, String>,
    val targetInventory: Map<String, String>, val sourceScan: ScanStats, val targetScan: ScanStats,
    val analysisDiagnostics: List<String>, val analysisMillis: Long, val createdAt: String,
    val rulesFile: Artifact? = null, val ruleOverrides: List<MigrationRuleOverride> = emptyList(), val engineBuildId: String,
) {
    fun fingerprint(): String = Digests.text(JsonFiles.encode(copy(runId = "", createdAt = "",
        sourceScan = sourceScan.copy(elapsedMillis = 0), targetScan = targetScan.copy(elapsedMillis = 0), analysisMillis = 0)))
}
data class MigrationReview(val taskId: String = "", val resolutionId: String = "", val ruleRevisionId: String = "",
    val action: ReviewAction = ReviewAction.DEFER, val level: Confidence = Confidence.LOW,
    val nameStillApplies: Boolean = false, val identityReason: String = "", val changes: List<String> = emptyList(),
    val unverified: List<String> = emptyList(), val evidenceIds: List<String> = emptyList(), val supersedes: String? = null)
data class MigrationReviewBatch(val schemaVersion: Int = SCHEMA_VERSION, val runId: String = "", val sourceKnowledgeId: String = "",
    val sourceApkSha256: String = "", val targetApkSha256: String = "", val items: List<MigrationReview> = emptyList())
data class MigrationDecision(val taskId: String, val name: String, val state: TaskState, val reason: String,
    val target: ClassRef?, val revisionId: String?, val review: MigrationReview?)
data class MigrationTaskView(val taskId: String, val name: String, val state: TaskState, val reason: String,
    val source: ClassRef, val captures: Map<String, String>, val resolution: Resolution, val revisionId: String?, val evidenceIds: List<String>)
data class MigrationTasksPage(val schemaVersion: Int = SCHEMA_VERSION, val runId: String, val total: Int, val offset: Int,
    val limit: Int, val tasks: List<MigrationTaskView>, val carriedUnresolved: List<UnresolvedKnowledge>)
data class MigrationSubmission(val schemaVersion: Int = SCHEMA_VERSION, val runId: String, val revisions: Map<String, String>, val decisions: List<MigrationDecision>)
data class MigrationPublication(val schemaVersion: Int = SCHEMA_VERSION, val runId: String, val knowledgeId: String,
    val outputDirectory: String, val accepted: Int, val unresolved: Int, val decisions: List<MigrationDecision>)
