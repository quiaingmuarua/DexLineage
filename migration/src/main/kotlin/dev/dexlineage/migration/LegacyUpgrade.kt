package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.rules.RuleEngine
import java.nio.file.Files
import java.nio.file.Path

internal typealias ResolutionExecutor = (Artifact, List<RuleRevision>, Path) -> ResolutionBatch
internal data class UpgradeDecision(val semanticId: String, val resolution: Resolution, val reusedReview: Boolean, val reason: String)
internal data class UpgradeResult(val knowledge: VersionKnowledge, val decisions: List<UpgradeDecision>)

/** Shared technical gate only; each explicit adapter validates its original semantic proof first. */
internal object LegacyUpgrade {
    fun publish(artifact: Artifact, entries: List<KnowledgeEntry>, unresolved: List<UnresolvedKnowledge>, sourceRoot: Path,
                out: Path, parentKnowledgeId: String, provenance: String, execute: ResolutionExecutor = ResolutionEngine::execute): UpgradeResult {
        entries.flatMap { it.locators }.forEach(RuleEngine::validate)
        val revisions = entries.associate { it.semanticId to RuleProofs.revision(it.locators) }
        val batch = execute(artifact, revisions.values.toList(), out.resolve("work/revalidation"))
        if (batch.scan.stats.diagnostics.isNotEmpty()) throw ExecutionException("Legacy revalidation scan incomplete")
        val claims = entries.associate { it.semanticId to AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) }
        requireInput(NameChecks.conflicts(claims, batch.scan.classes.keys).isEmpty(), "Legacy confirmed names or targets conflict")
        val accepted = mutableListOf<KnowledgeEntry>()
        val pending = unresolved.map { old -> old.copy(entry = copyEntry(old.entry, sourceRoot, out)) }.toMutableList()
        val decisions = entries.sortedBy { it.semanticId }.map { old ->
            val proof = batch.resolutions.getValue(revisions.getValue(old.semanticId).revisionId)
            RuleProofs.validate(proof)
            requireInput(proof.apkSha256 == artifact.sha256 && proof.rule == revisions.getValue(old.semanticId), "Legacy resolution input mismatch")
            val same = proof.status == ResolutionStatus.UNIQUE && proof.uniqueRef == old.binding
            val copied = copyEntry(old, sourceRoot, out)
            val reason = if (same) "unique_original_binding_review_reused" else if (proof.status == ResolutionStatus.UNIQUE) "unique_result_differs_from_original_binding" else "invalid_${proof.status.name.lowercase()}"
            if (same) accepted += copied.copy(ruleRevision = proof.rule, resolution = proof)
            else pending += UnresolvedKnowledge(copied, parentKnowledgeId, reason, sourceRoot.toAbsolutePath().normalize().toString())
            UpgradeDecision(old.semanticId, proof, same, reason)
        }
        Digests.verify(artifact)
        val value = KnowledgeFiles.write(out, VersionKnowledge(knowledgeId = "", artifact = artifact, entries = accepted,
            unresolved = pending, provenance = provenance, parentKnowledgeId = parentKnowledgeId))
        MappingOutput.write(out.resolve("mapping.tiny"), value.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        return UpgradeResult(value, decisions)
    }

    fun verifyTiny(path: Path, renames: List<AcceptedRename>) {
        val rows = Files.readAllLines(path)
        requireInput(rows.firstOrNull() == "tiny\t2\t0\tobfuscated\tnamed", "Unsupported legacy Tiny header")
        val pairs = rows.drop(1).filter { it.isNotEmpty() }.map { line ->
            val columns = line.split('\t')
            requireInput(columns.size == 3 && columns[0] == "c", "Legacy mapping contains non-class records")
            columns[1] to columns[2]
        }
        requireInput(pairs.map { it.first }.distinct().size == pairs.size, "Duplicate legacy Tiny classes")
        requireInput(pairs.toMap() == renames.associate { it.descriptor.substring(1, it.descriptor.length - 1) to it.newFullName.replace('.', '/') },
            "Legacy Mapping differs from confirmed bindings")
    }

    private fun copyEntry(entry: KnowledgeEntry, sourceRoot: Path, out: Path): KnowledgeEntry =
        entry.copy(evidence = entry.evidence.map { KnowledgeFiles.copyEvidence(sourceRoot, out, it) })
}
