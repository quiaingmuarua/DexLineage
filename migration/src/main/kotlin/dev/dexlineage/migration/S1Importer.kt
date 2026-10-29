package dev.dexlineage.migration

import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.knowledge.NameChecks
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.migration.legacy.Baseline
import dev.dexlineage.migration.legacy.DecisionStatus
import dev.dexlineage.migration.legacy.MigrationReport
import dev.dexlineage.migration.legacy.RunSnapshot
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path

/** Explicit conversion of validated S1 output; no S1 execution path is retained. */
object S1Importer {
    fun importKnowledge(outputDir: Path, oldRunDir: Path, outDir: Path): VersionKnowledge =
        importWithExecutor(outputDir, oldRunDir, outDir, ResolutionEngine::execute)

    internal fun importWithExecutor(outputDir: Path, oldRunDir: Path, outDir: Path, execute: ResolutionExecutor): VersionKnowledge = checkedInput("S1 import") {
        val run = JsonFiles.read(oldRunDir.resolve("run.json"), RunSnapshot::class.java, 1)
        val baseline = JsonFiles.read(outputDir.resolve("baseline.json"), Baseline::class.java, 1)
        val report = JsonFiles.read(outputDir.resolve("report.json"), MigrationReport::class.java, 1)
        requireInput(run.toolVersion == "0.1.0" && run.jadxVersion == "1.5.0" && run.policyVersion == 1, "Unsupported S1 version")
        requireInput(run.runId == run.fingerprint(), "S1 run fingerprint mismatch")
        listOf(run.sourceApk, run.targetApk, run.sourceJadx).forEach(Digests::verify)
        requireInput(run.sourceScan.diagnostics.isEmpty() && run.targetScan.diagnostics.isEmpty(), "Cannot import an incomplete S1 scan")
        requireInput(baseline.runId == run.runId && report.runId == run.runId, "S1 output belongs to another run")
        requireInput(baseline.artifact == run.targetApk && report.sourceApk == run.sourceApk && report.targetApk == run.targetApk, "S1 output APK mismatch")
        requireInput(report.sourceScan == run.sourceScan && report.targetScan == run.targetScan, "S1 report scan differs from run")
        requireInput(report.reviewSha256.matches(Regex("[a-f0-9]{64}")), "Invalid S1 review digest")
        val ids = run.items.map { it.id }
        requireInput(ids.distinct().size == ids.size && ids.all { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) }, "Invalid S1 item IDs")
        requireInput(baseline.items.map { it.id }.sorted() == ids.sorted() && report.decisions.map { it.id }.sorted() == ids.sorted(), "S1 output item set differs from run")
        val manualNames = readProjectNames(run)
        val entries = mutableListOf<KnowledgeEntry>()
        val pending = mutableListOf<UnresolvedKnowledge>()
        val evidenceToCopy = linkedMapOf<String, EvidenceRecord>()
        for (item in run.items.sortedBy { it.id }) {
            val b = baseline.items.single { it.id == item.id }
            val d = report.decisions.single { it.id == item.id }
            Identities.requireDescriptor(item.source.descriptor)
            requireInput(item.source.apkSha256 == run.sourceApk.sha256 && item.source.dexEntry.matches(Regex("classes(?:[0-9]+)?\\.dex")), "S1 source identity mismatch")
            requireInput(manualNames[item.source.descriptor] == item.semanticName, "S1 semantic name differs from the original JADX annotation")
            requireInput(item.rule.kind == "string" && item.rule.match == "exact" && item.rule.scope == "method_const_string" && item.rule.value.isNotBlank(), "Unsupported S1 rule")
            requireInput(item.sourceRuleValid == item.sourceCandidates.any { it.ref == item.source }, "S1 source rule validity is inconsistent")
            requireInput(item.targetCandidates.map { it.ref.descriptor }.distinct().size == item.targetCandidates.size, "Duplicate S1 candidates")
            (item.sourceCandidates to run.sourceApk).let { (candidates, apk) -> candidates.forEach { c ->
                requireInput(c.ref.apkSha256 == apk.sha256 && c.uses.isNotEmpty() && c.uses.all { it.classDescriptor == c.ref.descriptor && it.dexEntry == c.ref.dexEntry && it.literal == item.rule.value }, "Invalid S1 source candidate facts")
            } }
            item.targetCandidates.forEach { c -> requireInput(c.ref.apkSha256 == run.targetApk.sha256 && c.ref.descriptor in run.targetDescriptors && c.uses.isNotEmpty() && c.uses.all { it.classDescriptor == c.ref.descriptor && it.dexEntry == c.ref.dexEntry && it.literal == item.rule.value }, "Invalid S1 target candidate facts") }
            requireInput(b.semanticName == item.semanticName && d.semanticName == item.semanticName && b.source == item.source && d.source == item.source && b.rule == item.rule && d.rule == item.rule, "S1 item content differs from run: ${item.id}")
            requireInput(b.status == d.status && b.reason == d.reason && b.binding == d.target, "S1 baseline/report decision mismatch: ${item.id}")
            val review = d.review
            val proof = review?.let { r ->
                requireInput(r.id == item.id && r.evidenceIds.distinct().size == r.evidenceIds.size, "Invalid S1 review identity")
                r.targetDescriptor?.let { target -> requireInput(item.targetCandidates.any { it.ref.descriptor == target }, "S1 review target is not a candidate") }
                r.evidenceIds.map { id -> readEvidence(oldRunDir, run, id).also { e ->
                    requireInput(e.ref == item.source || item.targetCandidates.any { it.ref == e.ref }, "S1 review evidence belongs to another item")
                    evidenceToCopy[id] = e
                } }
            }.orEmpty()
            val last = KnowledgeEntry(item.id, item.semanticName, item.source, mapOf("literal" to item.rule.value),
                listOf(Locator("string-use", item.rule.value)), proof.filter { it.ref == item.source }.map(::asKnowledge),
                "Class name imported from the original JADX annotation", "s1:${run.runId}:${run.sourceJadx.sha256}")
            if (d.status == DecisionStatus.ACCEPTED) {
                requireInput(item.sourceRuleValid && item.targetCandidates.size == 1 && d.target == item.targetCandidates.single().ref, "S1 accepted binding was not a unique supported candidate")
                requireInput(review != null && review.targetDescriptor == d.target!!.descriptor && review.level == Confidence.HIGH && review.nameStillApplies && review.identityReason.isNotBlank(), "S1 acceptance review is incomplete")
                requireInput(proof.any { it.ref == item.source } && proof.any { it.ref == d.target }, "S1 acceptance lacks old/new evidence")
                requireInput(proof.none { it.incomplete } || review!!.unverified.any { it.isNotBlank() }, "S1 incomplete evidence was not acknowledged")
                entries += last.copy(binding = d.target!!, evidence = proof.map(::asKnowledge), rationale = review!!.identityReason)
            } else {
                requireInput(d.status == DecisionStatus.PENDING && d.target == null, "Unresolved S1 item has a target binding")
                val explanation = review?.let { "${d.reason}: ${it.identityReason}" } ?: d.reason
                pending += UnresolvedKnowledge(last, "s1:${run.runId}", explanation, oldRunDir.toAbsolutePath().normalize().toString())
            }
        }
        requireInput(report.accepted == entries.size && report.pending == pending.size, "S1 report totals differ from decisions")
        val renames = entries.associate { it.semanticId to AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) }
        requireInput(NameChecks.conflicts(renames, run.targetDescriptors.toSet()).isEmpty(), "S1 accepted mappings conflict")
        verifyTiny(outputDir.resolve("mapping.tiny"), renames.values.toList())
        createNewDirectory(outDir)
        evidenceToCopy.values.forEach { e -> copyEvidence(oldRunDir, outDir, e) }
        val upgraded = LegacyUpgrade.publish(run.targetApk, entries, pending, outDir, outDir, "s1:${run.runId}",
            "s1-import:${run.runId}:${Digests.file(outputDir.resolve("report.json"))}", execute)
        JsonFiles.writeNew(outDir.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "s1-import-report",
            "sourceRunId" to run.runId, "sourceOutput" to outputDir.toAbsolutePath().normalize().toString(), "knowledgeId" to upgraded.knowledge.knowledgeId,
            "legacyReport" to report, "decisions" to upgraded.decisions,
            "accepted" to upgraded.knowledge.entries.size, "unresolved" to upgraded.knowledge.unresolved.size))
        upgraded.knowledge
    }

    private fun readProjectNames(run: RunSnapshot): Map<String, String> {
        val path = Path.of(run.sourceJadx.path)
        val project = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(project["projectVersion"]?.asString == "1", "Only S1 projectVersion 1 is supported")
        val inputs = project.getAsJsonArray("files") ?: throw ValidationException("S1 JADX project inputs missing")
        requireInput(inputs.size() == 1 && inputs.single().isJsonPrimitive, "S1 JADX project must refer to one APK")
        val input = path.toAbsolutePath().parent.resolve(inputs.single().asString).normalize()
        requireInput(Digests.file(input) == run.sourceApk.sha256, "S1 JADX project APK differs from run")
        val selected = run.items.map { it.source.descriptor }.toSet()
        val names = linkedMapOf<String, String>()
        project.getAsJsonObject("codeData")?.getAsJsonArray("renames")?.forEach { element ->
            val rename = element.asJsonObject
            val ref = rename.getAsJsonObject("nodeRef")
            if (ref?.get("refType")?.asString == "CLASS") {
                val descriptor = Identities.descriptor(ref["declClass"].asString)
                if (descriptor in selected) {
                    requireInput(descriptor !in names, "Duplicate S1 class annotation")
                    val name = rename["newName"].asString
                    Identities.renamedFullName(descriptor, name)
                    names[descriptor] = name
                }
            }
        }
        return names
    }

    private fun readEvidence(root: Path, run: RunSnapshot, id: String): EvidenceRecord {
        requireInput(id.matches(Regex("[a-f0-9]{64}")), "Invalid S1 evidence ID")
        val nested = root.resolve("evidence/$id/record.json")
        val e = JsonFiles.read(if (Files.exists(nested)) nested else root.resolve("evidence/$id.json"), EvidenceRecord::class.java, 1)
        requireInput(e.evidenceId == id && e.runId == run.runId && id == Identities.evidenceId(run.runId, e.ref), "S1 evidence identity mismatch")
        requireInput(e.javaPath in listOf("evidence/$id/code.java", "evidence/$id.java"), "Invalid S1 evidence Java path")
        requireInput(Digests.file(root.resolve(e.javaPath)) == e.javaSha256, "S1 evidence Java content changed")
        if (e.smaliPath != null) {
            requireInput(e.smaliPath in listOf("evidence/$id/code.smali", "evidence/$id.smali"), "Invalid S1 evidence Smali path")
            requireInput(Digests.file(root.resolve(e.smaliPath)) == e.smaliSha256, "S1 evidence Smali content changed")
        } else requireInput(e.smaliSha256 == null, "S1 Smali hash has no file")
        return e
    }
    private fun asKnowledge(e: EvidenceRecord) = KnowledgeEvidence(e.evidenceId, e.ref, "evidence/${e.evidenceId}/code.java", e.javaSha256,
        e.smaliPath?.let { "evidence/${e.evidenceId}/code.smali" }, e.smaliSha256, e.incomplete, e.diagnostics)
    private fun copyEvidence(source: Path, out: Path, e: EvidenceRecord) {
        val target = asKnowledge(e)
        Files.createDirectories(out.resolve("evidence/${e.evidenceId}"))
        Files.copy(source.resolve(e.javaPath), out.resolve(target.javaPath))
        e.smaliPath?.let { Files.copy(source.resolve(it), out.resolve(target.smaliPath!!)) }
    }
    /** S1 wrote exactly this class-only Tiny subset; reject members/extra namespaces rather than guessing. */
    private fun verifyTiny(path: Path, renames: List<AcceptedRename>) {
        val rows = Files.readAllLines(path)
        requireInput(rows.firstOrNull() == "tiny\t2\t0\tobfuscated\tnamed", "Unsupported S1 Tiny header")
        val pairs = rows.drop(1).filter { it.isNotEmpty() }.map { line ->
            val columns = line.split('\t')
            requireInput(columns.size == 3 && columns[0] == "c", "S1 mapping contains non-class records")
            columns[1] to columns[2]
        }
        requireInput(pairs.map { it.first }.distinct().size == pairs.size, "Duplicate S1 Tiny classes")
        val expected = renames.associate { it.descriptor.substring(1, it.descriptor.length - 1) to it.newFullName.replace('.', '/') }
        requireInput(pairs.toMap() == expected, "S1 Mapping differs from confirmed bindings")
    }
}
