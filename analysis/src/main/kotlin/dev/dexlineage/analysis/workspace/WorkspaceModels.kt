package dev.dexlineage.analysis.workspace

import dev.dexlineage.analysis.AnalysisMethodPlan
import dev.dexlineage.model.Artifact
import dev.dexlineage.model.SCHEMA_VERSION

data class WorkspaceConfig(val schemaVersion: Int = SCHEMA_VERSION, val apk: String,
    val baseKnowledge: String? = null, val referenceKnowledge: List<String> = emptyList(),
    val profile: String, val seedRules: String? = null, val corpus: String? = null)

data class WorkspaceInputs(val configFile: Artifact, val config: WorkspaceConfig, val apk: Artifact,
    val baseKnowledge: Artifact?, val referenceKnowledge: List<Artifact>, val method: AnalysisMethodPlan,
    val inputFiles: List<Artifact>, val implementationId: String, val engineBuildId: String, val corpusFile: Artifact? = null)

enum class WorkspaceState { RUNNING, WAITING_DEPENDENCY, WAITING_REVIEW, COMPLETE, FAILED }
enum class WorkspaceStageKind { SEED, DISCOVERY, PREPARE, PACKET, REVIEW_HEADS, PUBLICATION }

data class WorkspaceFile(val path: String, val sha256: String)
data class WorkspaceAttempt(val number: Int, val path: String, val state: String = "STARTED", val error: String? = null)
data class WorkspaceStage(val id: String, val kind: WorkspaceStageKind, val seedIndex: Int? = null,
    val attempts: List<WorkspaceAttempt> = emptyList(), val receipt: WorkspaceFile? = null)
data class WorkspaceRecord(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-workspace",
    val workspaceId: String, val inputs: WorkspaceInputs, val stages: List<WorkspaceStage>,
    val state: WorkspaceState = WorkspaceState.RUNNING, val message: String? = null)

data class WorkspaceProduct(val runPath: String? = null, val discoveryPath: String? = null, val rulesPath: String? = null,
    val packetPath: String? = null, val knowledgePath: String? = null, val reviewHeadsPath: String? = null,
    val runId: String? = null, val knowledgeId: String? = null, val selectedTaskIds: List<String> = emptyList())
data class WorkspaceReceipt(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = "analysis-workspace-receipt",
    val workspaceId: String, val stageId: String, val attempt: Int, val implementationId: String,
    val product: WorkspaceProduct, val files: List<WorkspaceFile>)

data class WorkspaceStageStatus(val id: String, val kind: WorkspaceStageKind, val state: String,
    val attempts: List<WorkspaceAttempt>, val receiptPath: String?, val product: WorkspaceProduct?)
data class WorkspaceStatus(val schemaVersion: Int = SCHEMA_VERSION, val workspaceId: String, val methodId: String,
    val state: WorkspaceState, val workspacePath: String, val runPath: String?, val packetPath: String?,
    val knowledgePath: String?, val discoveryPath: String?, val reviewHeadsPath: String?,
    val selectedTaskIds: List<String>, val pendingTaskIds: List<String>, val waitingTaskIds: List<String>,
    val stages: List<WorkspaceStageStatus>, val message: String?)

internal data class WorkspaceReviewGate(val selected: List<String>, val unreviewed: List<String>, val waiting: List<String>)
