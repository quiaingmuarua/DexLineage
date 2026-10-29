package dev.dexlineage.migration.legacy

import dev.dexlineage.io.Digests
import dev.dexlineage.io.JsonFiles
import dev.dexlineage.model.*

/** Read-only wire types for the explicit S1 import boundary. Not a second workflow. */
data class StringRule(val value: String, val kind: String = "string", val match: String = "exact", val scope: String = "method_const_string")
data class Candidate(val ref: ClassRef, val uses: List<StringUseSite>)
data class RunItem(val id: String, val semanticName: String, val source: ClassRef, val rule: StringRule,
    val sourceRuleValid: Boolean, val sourceCandidates: List<Candidate>, val targetCandidates: List<Candidate>)
data class RunSnapshot(val schemaVersion: Int = 1, val runId: String, val caseId: String,
    val toolVersion: String = "0.1.0", val jadxVersion: String = "1.5.0", val policyVersion: Int = 1,
    val sourceApk: Artifact, val targetApk: Artifact, val sourceJadx: Artifact, val items: List<RunItem>,
    val targetDescriptors: List<String>, val sourceScan: ScanStats, val targetScan: ScanStats, val createdAt: String) {
    fun fingerprint(): String = Digests.text(JsonFiles.encode(copy(runId = "", createdAt = "",
        sourceScan = sourceScan.copy(elapsedMillis = 0), targetScan = targetScan.copy(elapsedMillis = 0))))
}
data class ReviewItem(val id: String, val targetDescriptor: String?, val level: Confidence, val nameStillApplies: Boolean,
    val identityReason: String, val changes: List<String>, val unverified: List<String>, val evidenceIds: List<String>)
enum class DecisionStatus { ACCEPTED, PENDING }
data class Decision(val id: String, val semanticName: String, val status: DecisionStatus, val reason: String,
    val source: ClassRef, val rule: StringRule, val target: ClassRef?, val review: ReviewItem?)
data class BaselineItem(val id: String, val semanticName: String, val status: DecisionStatus, val reason: String,
    val source: ClassRef, val rule: StringRule, val binding: ClassRef?)
data class Baseline(val schemaVersion: Int = 1, val runId: String, val artifact: Artifact, val items: List<BaselineItem>)
data class MigrationReport(val schemaVersion: Int = 1, val runId: String, val sourceApk: Artifact, val targetApk: Artifact,
    val reviewSha256: String, val accepted: Int, val pending: Int, val decisions: List<Decision>, val sourceScan: ScanStats, val targetScan: ScanStats)
