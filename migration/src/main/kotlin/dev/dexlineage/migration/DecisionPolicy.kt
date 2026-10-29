package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.NameChecks
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*

/** The executable resolution determines identity; review determines semantic continuity. */
object DecisionPolicy {
    fun validateReview(run: MigrationRun, task: MigrationTask, review: MigrationReview, evidence: Map<String, EvidenceRecord>) = checkedInput("migration review") {
        requireInput(review.taskId == task.taskId, "Review task identity mismatch")
        requireInput(review.resolutionId == task.resolution.resolutionId && review.ruleRevisionId == task.resolution.rule.revisionId,
            "Review refers to another resolution or rule revision")
        val action: ReviewAction? = review.action
        val level: Confidence? = review.level
        val changes: List<String?>? = review.changes
        val unverified: List<String?>? = review.unverified
        val ids: List<String?>? = review.evidenceIds
        requireInput(action != null && level != null, "Missing action/confidence")
        requireInput(review.identityReason.isNotBlank(), "A review rationale is required")
        requireInput(changes != null && changes.none { it == null } && unverified != null && unverified.none { it == null }, "Invalid review explanation lists")
        requireInput(ids != null && ids.none { it == null } && ids.distinct().size == ids.size, "Invalid or duplicate evidence references")
        requireInput(action != ReviewAction.ACCEPT || task.resolution.status == ResolutionStatus.UNIQUE, "Cannot ACCEPT invalid resolution: ${task.resolution.status}")
        val allowed = allowedEvidence(run, task)
        review.evidenceIds.forEach { id ->
            val e = evidence[id] ?: throw ValidationException("Unknown evidence: $id")
            requireInput(e.schemaVersion == SCHEMA_VERSION && e.runId == run.runId && e.evidenceId == id, "Evidence belongs to another run")
            requireInput(id == Identities.evidenceId(run.runId, e.ref) && e.ref in allowed, "Evidence does not belong to this migration task")
        }
    }

    fun decide(run: MigrationRun, reviews: Map<String, Pair<String, MigrationReview>>, evidence: Map<String, EvidenceRecord>): List<MigrationDecision> = checkedInput("migration decisions") {
        requireInput(run.sourceScan.diagnostics.isEmpty() && run.targetScan.diagnostics.isEmpty(), "Cannot decide an incomplete DEX scan")
        requireInput(reviews.keys.all { id -> run.tasks.any { it.taskId == id } }, "Unknown reviewed task")
        val initial = run.tasks.sortedBy { it.taskId }.map { task ->
            RuleProofs.validate(task.resolution)
            val pair = reviews[task.taskId]
            val r = pair?.second
            if (r != null) validateReview(run, task, r, evidence)
            val selected = task.resolution.uniqueRef
            val records = r?.evidenceIds.orEmpty().map(evidence::getValue)
            val reason = when {
                task.resolution.status != ResolutionStatus.UNIQUE -> "invalid_${task.resolution.status.name.lowercase()}"
                r == null -> "unreviewed"
                r.action == ReviewAction.REJECT -> "review_rejected"
                r.action == ReviewAction.DEFER -> "review_deferred"
                r.level.ordinal > run.minConfidence.ordinal -> "confidence_below_threshold"
                !r.nameStillApplies -> "name_no_longer_applies"
                records.none { it.ref == task.entry.binding } -> "source_evidence_missing"
                records.none { it.ref == selected } -> "target_evidence_missing"
                records.any { it.incomplete } && r.unverified.none { it.isNotBlank() } -> "incomplete_evidence_not_acknowledged"
                else -> "review_supported_continuity"
            }
            val state = when {
                task.resolution.status != ResolutionStatus.UNIQUE -> TaskState.INVALID
                r == null -> TaskState.UNREVIEWED
                r.action == ReviewAction.REJECT -> TaskState.REJECTED
                reason == "review_supported_continuity" -> TaskState.ACCEPTED
                else -> TaskState.DEFERRED
            }
            MigrationDecision(task.taskId, task.entry.name, state, reason, if (state == TaskState.ACCEPTED) selected else null, pair?.first, r)
        }
        val renames = initial.filter { it.state == TaskState.ACCEPTED }.associate { d ->
            d.taskId to AcceptedRename(d.target!!.descriptor, Identities.renamedFullName(d.target.descriptor, d.name))
        }
        val conflicts = NameChecks.conflicts(renames, run.targetInventory.keys)
        initial.map { d -> conflicts[d.taskId]?.let { d.copy(state = TaskState.DEFERRED, reason = it, target = null) } ?: d }
    }

    fun allowedEvidence(run: MigrationRun, task: MigrationTask): Set<ClassRef> = buildSet {
        add(task.entry.binding)
        addAll(task.entry.evidence.filter { it.ref.apkSha256 == run.sourceApk.sha256 }.map { it.ref })
        task.candidates.forEach { candidate ->
            add(candidate.ref)
            candidate.matches.mapNotNull { it.field?.call?.declaringType }.distinct().forEach { type ->
                run.targetInventory[type]?.let { dex -> add(ClassRef(run.targetApk.sha256, type, dex)) }
            }
        }
    }
}
