package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.NameChecks
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.model.*

/** The executable resolution determines identity; review determines semantic continuity. */
object DecisionPolicy {
    fun validateReview(run: MigrationRun, task: MigrationTask, review: MigrationReview, evidence: Map<String, EvidenceRecord>) = checkedInput("migration review") {
        requireInput(review.taskId == task.taskId, "Review task identity mismatch")
        val resolution = task.resolution ?: throw ValidationException("Task is waiting for dependencies; no Resolution exists")
        requireInput(task.inheritedEntry == null, "Inherited target has no new review task; revise its rule to request an update")
        requireInput(review.resolutionId == resolution.resolutionId && review.ruleRevisionId == resolution.rule.revisionId,
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
        requireInput(action != ReviewAction.ACCEPT || resolution.status == ResolutionStatus.UNIQUE, "Cannot ACCEPT invalid resolution: ${resolution.status}")
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
            task.inheritedEntry?.let { inherited ->
                requireInput(task.taskId !in reviews, "Inherited target cannot receive a new review")
                return@map MigrationDecision(task.taskId, inherited.name, TaskState.ACCEPTED, "inherited_confirmed", inherited.binding, null, null)
            }
            val resolution = task.resolution
            if (resolution == null) {
                requireInput(task.taskId !in reviews, "Waiting task cannot receive a review")
                return@map MigrationDecision(task.taskId, task.entry.name, TaskState.DEFERRED, "waiting_dependency", null, null, null)
            }
            RuleProofs.validate(resolution)
            val pair = reviews[task.taskId]
            val r = pair?.second
            if (r != null) validateReview(run, task, r, evidence)
            val selected = resolution.uniqueRef
            val existing = run.targetBase?.entries?.singleOrNull { it.semanticId == task.taskId }
            val occupied = run.targetBase?.entries?.singleOrNull { it.binding == selected && it.semanticId != task.taskId }
            val records = r?.evidenceIds.orEmpty().map(evidence::getValue)
            val reason = when {
                resolution.status != ResolutionStatus.UNIQUE -> "invalid_${resolution.status.name.lowercase()}"
                existing != null && existing.binding != selected -> "existing_target_binding_changed"
                occupied != null -> "target_conflict"
                r == null -> "unreviewed"
                r.action == ReviewAction.REJECT -> "review_rejected"
                r.action == ReviewAction.DEFER -> "review_deferred"
                r.level.ordinal > run.minConfidence.ordinal -> "confidence_below_threshold"
                !r.nameStillApplies -> "name_no_longer_applies"
                records.none { it.ref == task.entry.binding } -> "source_evidence_missing"
                records.none { it.ref == selected } -> "target_evidence_missing"
                requiredTargetEvidence(run, task).any { ref -> records.none { it.ref == ref } } -> "dependency_or_relation_evidence_missing"
                records.any { it.incomplete } && r.unverified.none { it.isNotBlank() } -> "incomplete_evidence_not_acknowledged"
                else -> "review_supported_continuity"
            }
            val state = when {
                resolution.status != ResolutionStatus.UNIQUE -> TaskState.INVALID
                r == null -> TaskState.UNREVIEWED
                r.action == ReviewAction.REJECT -> TaskState.REJECTED
                reason == "review_supported_continuity" -> TaskState.ACCEPTED
                else -> TaskState.DEFERRED
            }
            MigrationDecision(task.taskId, task.entry.name, state, reason, if (state == TaskState.ACCEPTED) selected else null, pair?.first, r)
        }
        val renames = initial.filter { it.state == TaskState.ACCEPTED && it.reason != "inherited_confirmed" }.associate { d ->
            d.taskId to AcceptedRename(d.target!!.descriptor, Identities.renamedFullName(d.target.descriptor, d.name))
        }
        val baseline = run.targetBase?.entries.orEmpty().associate { it.binding.descriptor to Identities.renamedFullName(it.binding.descriptor, it.name) }
        val conflicts = NameChecks.conflicts(renames, run.targetInventory.keys, baseline)
        initial.map { d -> conflicts[d.taskId]?.let { d.copy(state = TaskState.DEFERRED, reason = it, target = null) } ?: d }
    }

    fun allowedEvidence(run: MigrationRun, task: MigrationTask): Set<ClassRef> = buildSet {
        add(task.entry.binding)
        addAll(KnowledgeFiles.evidenceClosure(task.entry).filter { it.ref.apkSha256 == run.sourceApk.sha256 }.map { it.ref })
        task.resolution?.let { proof -> addAll(KnowledgeFiles.evidenceClosure(proof).filter { it.ref.apkSha256 == run.targetApk.sha256 }.map { it.ref }) }
        task.candidates.forEach { candidate ->
            add(candidate.ref)
            addAll(candidate.matches.flatMap { it.relatedRefs })
            addAll(candidate.matches.flatMap { fact -> fact.trace.map { it.owner } })
            candidate.matches.mapNotNull { it.field?.call?.declaringType }.distinct().forEach { type ->
                run.targetInventory[type]?.let { dex -> add(ClassRef(run.targetApk.sha256, type, dex)) }
            }
        }
    }

    internal fun requiredTargetEvidence(run: MigrationRun, task: MigrationTask): Set<ClassRef> = buildSet {
        val proof = task.resolution ?: return@buildSet
        proof.uniqueRef?.let(::add)
        addAll(KnowledgeFiles.evidenceClosure(proof).filter { it.ref.apkSha256 == run.targetApk.sha256 }.map { it.ref })
        proof.dependencies.values.forEach { add(it.binding.owner) }
        proof.matches.filter { it.owner == proof.uniqueRef && it.status == MatchStatus.PASS }.forEach { fact ->
            addAll(fact.relatedRefs)
            addAll(fact.trace.map { it.owner })
            fact.field?.call?.declaringType?.let { raw -> run.targetInventory[raw]?.let { add(ClassRef(run.targetApk.sha256, raw, it)) } }
        }
    }
}
