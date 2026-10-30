package dev.dexlineage.analysis

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.NameChecks
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.model.*

internal object AnalysisPolicy {
    fun decide(run: AnalysisRun, reviews: Map<String, AnalysisReview>, evidence: Map<String, EvidenceRecord>): List<AnalysisDecision> = checkedInput("Analysis reviews") {
        val tasks = run.tasks.associateBy { it.taskId }
        requireInput(reviews.keys.all { it in tasks }, "Review refers to an unknown Analysis task")
        reviews.forEach { (id, review) -> validateReview(run, tasks.getValue(id), review, evidence) }
        val initial = run.tasks.sortedBy { it.taskId }.map { task ->
            val review = reviews[task.taskId]
            val proof = task.resolution
            val reason = when {
                task.executionState == AnalysisExecutionState.WAITING_DEPENDENCY -> "waiting_dependency"
                task.executionState == AnalysisExecutionState.INHERITED -> "inherited_confirmation"
                task.invalidReason != null -> task.invalidReason
                proof?.status != ResolutionStatus.UNIQUE -> "resolution_${proof?.status?.name?.lowercase()}"
                review == null -> "review_missing"
                review.action == ReviewAction.REJECT -> "review_rejected"
                review.action == ReviewAction.DEFER -> "review_deferred"
                review.level.ordinal > run.rules.minConfidence.ordinal -> "confidence_below_threshold"
                review.name.isNullOrBlank() -> "name_missing"
                requiresFactory(task) && factories(run, task).isEmpty() -> "factory_evidence_unavailable"
                requiredRefs(run, task).any { ref -> review.evidenceIds.none { evidence.getValue(it).ref == ref } } -> "owner_or_factory_evidence_missing"
                review.evidenceIds.any { evidence.getValue(it).incomplete } && review.unverified.none { it.isNotBlank() } -> "incomplete_evidence_not_acknowledged"
                else -> "review_supported_name"
            }
            val state = when {
                task.executionState == AnalysisExecutionState.WAITING_DEPENDENCY -> TaskState.DEFERRED
                task.executionState == AnalysisExecutionState.INHERITED -> TaskState.ACCEPTED
                task.invalidReason != null || proof?.status != ResolutionStatus.UNIQUE -> TaskState.INVALID
                review == null -> TaskState.UNREVIEWED
                review.action == ReviewAction.REJECT -> TaskState.REJECTED
                reason == "review_supported_name" -> TaskState.ACCEPTED
                else -> TaskState.DEFERRED
            }
            AnalysisDecision(task.taskId, state, reason, task.semanticId,
                if (state == TaskState.ACCEPTED) proof?.uniqueRef else null,
                if (task.executionState == AnalysisExecutionState.INHERITED) task.existingEntry!!.name else if (state == TaskState.ACCEPTED) review!!.name else null, review)
        }
        val renames = initial.filter { it.state == TaskState.ACCEPTED && tasks.getValue(it.taskId).executionState != AnalysisExecutionState.INHERITED }.associate { d ->
            d.taskId to AcceptedRename(d.target!!.descriptor, Identities.renamedFullName(d.target.descriptor, d.name!!))
        }
        val baselineNames = run.baseKnowledge?.entries.orEmpty().associate { it.binding.descriptor to Identities.renamedFullName(it.binding.descriptor, it.name) }
        val conflicts = NameChecks.conflicts(renames, run.classInventory.keys, baselineNames)
        initial.map { decision -> conflicts[decision.taskId]?.let { decision.copy(state = TaskState.DEFERRED, reason = it, target = null, name = null) } ?: decision }
    }

    fun validateReview(run: AnalysisRun, task: AnalysisTask, review: AnalysisReview, evidence: Map<String, EvidenceRecord>) = checkedInput("Analysis review") {
        requireInput(review.taskId == task.taskId, "Review task identity mismatch")
        requireInput(task.executionState == AnalysisExecutionState.EXECUTED, "Only an executed class target accepts Review; inherited or waiting tasks need a new execution")
        val proof = task.resolution ?: throw ValidationException("Task has no matching execution")
        requireInput(review.resolutionId == proof.resolutionId && review.ruleRevisionId == task.rule.revisionId, "Review belongs to another matching execution or rule revision")
        val action: ReviewAction? = review.action
        val level: Confidence? = review.level
        val ids: List<String?>? = review.evidenceIds
        val unverified: List<String?>? = review.unverified
        requireInput(action != null && level != null && !review.rationale.isNullOrBlank(), "Analysis review requires action, confidence and rationale")
        requireInput(ids != null && ids.none { it == null } && ids.distinct().size == ids.size, "Invalid evidence references")
        requireInput(unverified != null && unverified.none { it == null }, "Invalid unverified list")
        if (action == ReviewAction.ACCEPT) {
            requireInput(task.invalidReason == null && proof.status == ResolutionStatus.UNIQUE, "Cannot accept an invalid matching result")
            if (task.identitySourceKnowledgeId != null) requireInput(review.name == task.existingEntry?.name,
                "Referenced canonical name must be retained; defer a disputed identity instead of renaming it in the theme package")
        }
        review.name?.let { Identities.renamedFullName(proof.uniqueRef?.descriptor ?: "Lvalidation;", it) }
        val allowed = allowedRefs(run, task)
        review.evidenceIds.forEach { id ->
            val record = evidence[id] ?: throw ValidationException("Unknown evidence: $id")
            requireInput(record.runId == run.runId && record.evidenceId == Identities.evidenceId(run.runId, record.ref), "Evidence belongs to another run")
            requireInput(record.ref.apkSha256 == run.apk.sha256 && record.ref in allowed, "Evidence is not for this task's candidate or factory")
        }
    }

    fun allowedRefs(run: AnalysisRun, task: AnalysisTask): Set<ClassRef> = buildSet {
        addAll(task.resolution?.candidates.orEmpty().map { it.ref })
        task.resolution?.let { addAll(proofRefs(it)) }
        task.resolution?.unresolvedPaths.orEmpty().forEach { add(it.source.owner) }
        task.expectedOwner?.let(::add)
        task.existingEntry?.let { entry ->
            add(entry.binding)
            addAll(entry.evidence.filter { it.ref.apkSha256 == run.apk.sha256 }.map { it.ref })
        }
        task.resolution?.candidates.orEmpty().flatMap { it.matches }.mapNotNull { it.field?.call?.declaringType }.distinct().forEach { descriptor ->
            run.classInventory[descriptor]?.let { add(ClassRef(run.apk.sha256, descriptor, it)) }
        }
    }
    private fun requiresFactory(task: AnalysisTask): Boolean = task.resolution?.let { proof -> proof.matches.any { it.owner == proof.uniqueRef && it.status == MatchStatus.PASS && it.field?.call != null } } ?: false
    private fun factories(run: AnalysisRun, task: AnalysisTask): Set<ClassRef> = task.resolution?.matches.orEmpty()
        .filter { it.owner == task.resolution?.uniqueRef && it.status == MatchStatus.PASS }
        .mapNotNull { it.field?.call?.declaringType }.distinct().mapNotNull { descriptor ->
            run.classInventory[descriptor]?.let { ClassRef(run.apk.sha256, descriptor, it) }
        }.toSet()
    private fun requiredRefs(run: AnalysisRun, task: AnalysisTask): Set<ClassRef> = setOfNotNull(task.resolution?.uniqueRef) + factories(run, task) +
        task.resolution?.let(::proofRefs).orEmpty()

    /** Both the selected entity and the resolved dependency chain are part of semantic review. */
    internal fun proofRefs(proof: Resolution): Set<ClassRef> = buildSet {
        val selected = proof.uniqueEntity
        proof.matches.filter { it.status == MatchStatus.PASS && (selected == null || it.owner == selected.owner && it.method == selected.method) }
            .forEach { addAll(it.relatedRefs); addAll(it.trace.map { trace -> trace.owner }) }
        proof.dependencies.values.forEach { anchor ->
            add(anchor.binding.owner)
            addAll(KnowledgeFiles.evidenceClosure(anchor).map { it.ref })
        }
    }
}
