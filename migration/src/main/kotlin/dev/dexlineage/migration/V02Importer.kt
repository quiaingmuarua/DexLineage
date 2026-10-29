package dev.dexlineage.migration

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.rules.RuleJson
import java.nio.file.Files
import java.nio.file.Path

/** Explicit schema-2 publication adapter. Historical decisions are checked, never executed as v0.3 reviews. */
object V02Importer {
    fun importKnowledge(knowledgePath: Path, apkPath: Path, out: Path): VersionKnowledge =
        importWithExecutor(knowledgePath, apkPath, out, ResolutionEngine::execute)

    internal fun importWithExecutor(knowledgePath: Path, apkPath: Path, out: Path, execute: ResolutionExecutor): VersionKnowledge = checkedInput("v0.2 import") {
        val source = knowledgePath.toAbsolutePath().parent
        val inputArtifacts = listOf(knowledgePath, source.resolve("report.json"), source.resolve("mapping.tiny")).map(Digests::artifact)
        val raw = JsonParser.parseString(Files.readString(knowledgePath)).asJsonObject
        requireInput(raw["schemaVersion"]?.asString == "2" && raw["kind"]?.asString == "version-knowledge", "Expected schemaVersion 2 VersionKnowledge")
        requireInput(!raw.has("parentKnowledgeId") && raw.getAsJsonArray("entries").all { e -> !e.asJsonObject.has("resolution") && !e.asJsonObject.has("ruleRevision") }, "v0.2 input contains newer proof fields")
        val oldId = raw["knowledgeId"].asString
        val fingerprint = raw.deepCopy().apply { addProperty("knowledgeId", "") }
        requireInput(oldId == Digests.text(JsonFiles.encode(fingerprint)), "v0.2 knowledge fingerprint mismatch")
        val rawEntries = raw.getAsJsonArray("entries").map { it.asJsonObject } + raw.getAsJsonArray("unresolved").map { it.asJsonObject.getAsJsonObject("entry") }
        rawEntries.forEach { RuleJson.validateLocators(it["locators"] ?: throw ValidationException("Missing legacy locators")) }
        val knowledge = JsonFiles.gson.fromJson(raw, VersionKnowledge::class.java)
        val artifact = Digests.artifact(apkPath)
        requireInput(artifact.sha256 == knowledge.artifact.sha256, "Provided APK does not match v0.2 knowledge")
        val allIds = knowledge.entries.map { it.semanticId } + knowledge.unresolved.map { it.entry.semanticId }
        requireInput(allIds.distinct().size == allIds.size, "Duplicate v0.2 semantic identity")
        knowledge.unresolved.forEach { requireInput(it.sourceKnowledgeId.isNotBlank() && it.reason.isNotBlank() && it.originRun.isNotBlank(), "Legacy unresolved knowledge lacks its source") }
        val allEntries = knowledge.entries + knowledge.unresolved.map { it.entry }
        allEntries.forEach { entry ->
            requireInput(entry.semanticId.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) && entry.locators.isNotEmpty(), "Invalid legacy identity or missing locators")
            Identities.renamedFullName(entry.binding.descriptor, entry.name)
            requireInput(entry.evidence.map { it.evidenceId }.distinct().size == entry.evidence.size, "Duplicate legacy evidence")
            entry.evidence.forEach { verifyEvidence(source, it) }
        }
        knowledge.entries.forEach { entry ->
            requireInput(entry.binding.apkSha256 == artifact.sha256 && entry.evidence.any { it.ref == entry.binding }, "Legacy current binding lacks owner evidence or has another APK")
        }
        val report = JsonParser.parseString(Files.readString(source.resolve("report.json"))).asJsonObject
        requireInput(report["schemaVersion"]?.asString == "2" && report["knowledgeId"]?.asString == oldId, "Legacy report/knowledge identity mismatch")
        val scenario = when {
            report["scenario"]?.asString == "bootstrap" -> "bootstrap"
            report["kind"]?.asString == "migration-report" -> "migration"
            else -> throw ValidationException("Unsupported v0.2 report; original S1 results must use knowledge import-s1")
        }
        val reportArtifact = parse<Artifact>(report, if (scenario == "bootstrap") "apk" else "targetApk", Artifact::class.java)
        requireInput(reportArtifact == knowledge.artifact, "Legacy report APK differs from knowledge")
        val runId = report["runId"].asString
        requireInput(knowledge.provenance == "$scenario:$runId", "Legacy knowledge provenance mismatch")
        val decisions = report.getAsJsonArray("decisions").map { it.asJsonObject }
        requireInput(decisions.map { it["taskId"].asString }.distinct().size == decisions.size, "Duplicate legacy report decisions")
        requireInput(decisions.all { it["state"].asString in setOf("UNREVIEWED", "ACCEPTED", "REJECTED", "DEFERRED") }, "Unsupported legacy review state")
        val accepted = decisions.filter { it["state"].asString == "ACCEPTED" }
        requireInput(accepted.size == knowledge.entries.size, "Legacy report accepted count differs from knowledge")
        if (scenario == "bootstrap") {
            requireInput(knowledge.unresolved.isEmpty(), "v0.2 Bootstrap publication cannot contain unresolved historical knowledge")
            requireInput(report.getAsJsonObject("scan").getAsJsonArray("diagnostics").size() == 0, "Legacy Bootstrap scan incomplete")
            val counts = report.getAsJsonObject("counts")
            for (state in listOf("UNREVIEWED", "ACCEPTED", "REJECTED", "DEFERRED")) requireInput(counts[state]?.asInt == decisions.count { it["state"].asString == state }, "Legacy Bootstrap report totals differ from decisions")
        } else {
            requireInput(report["accepted"]?.asInt == knowledge.entries.size && report["unresolved"]?.asInt == knowledge.unresolved.size, "Legacy migration report totals differ from knowledge")
            val tasks = report.getAsJsonArray("tasks").map { it.asJsonObject }
            val taskIds = tasks.map { it["taskId"].asString }
            requireInput(taskIds.distinct().size == taskIds.size && taskIds.toSet() == decisions.map { it["taskId"].asString }.toSet(), "Legacy migration task/decision set differs")
            val pendingIds = knowledge.unresolved.map { it.entry.semanticId }.toSet()
            val acceptedIds = knowledge.entries.map { it.semanticId }.toSet()
            requireInput(acceptedIds.all { it in taskIds } && taskIds.all { it in acceptedIds || it in pendingIds }, "Legacy migration lost task knowledge")
            val sourceKnowledgeId = report["sourceKnowledgeId"].asString
            tasks.filter { it["taskId"].asString !in acceptedIds }.forEach { task ->
                val id = task["taskId"].asString
                val original = parse(task, "entry", KnowledgeEntry::class.java)
                val pending = knowledge.unresolved.single { it.entry.semanticId == id }
                val decision = decisions.single { it["taskId"].asString == id }
                requireInput(pending.entry == original && pending.sourceKnowledgeId == sourceKnowledgeId, "Legacy pending entry differs from its last confirmed source")
                requireInput(!decision.has("target") || decision["target"].isJsonNull, "Legacy pending decision has a current target")
                val expectedReason = decision["reason"].asString
                requireInput(pending.reason == expectedReason || pending.reason.startsWith("$expectedReason: "), "Legacy pending reason differs from decision")
            }
            requireInput(report["carriedUnresolved"]?.asInt == knowledge.unresolved.count { it.entry.semanticId !in taskIds }, "Legacy carried unresolved count mismatch")
        }
        val revisions = report.getAsJsonObject("reviewRevisions")
        knowledge.entries.forEach { entry ->
            val taskId = if (scenario == "bootstrap") Digests.text("bootstrap-task\n${artifact.sha256}\n${entry.binding.descriptor}") else entry.semanticId
            val d = accepted.singleOrNull { it["taskId"].asString == taskId } ?: throw ValidationException("Legacy entry has no accepted decision: ${entry.semanticId}")
            requireInput(d["name"].asString == entry.name, "Legacy decision name differs from knowledge")
            val review = d.getAsJsonObject("review") ?: throw ValidationException("Missing original semantic review")
            requireInput(review["taskId"].asString == taskId && review["action"].asString == "ACCEPT", "Legacy semantic review identity/action mismatch")
            val level = Confidence.valueOf(review["level"].asString)
            val supersedes = review["supersedes"]?.takeUnless { it.isJsonNull }?.asString
            val draft = StoredReview(schemaVersion = 2, revisionId = "", runId = runId, taskId = taskId, supersedes = supersedes, payload = review)
            val revision = Digests.text(JsonFiles.encode(draft))
            requireInput(revisions[taskId]?.asString == revision && entry.provenance == "$scenario:$runId:$revision", "Legacy review revision/provenance mismatch")
            val ids = stringList(review, "evidenceIds")
            requireInput(ids.distinct().size == ids.size, "Duplicate legacy review evidence")
            val evidence = entry.evidence.associateBy { it.evidenceId }
            requireInput(ids.all { it in evidence }, "Legacy review references absent evidence")
            evidence.values.forEach { e -> requireInput(e.evidenceId == Identities.evidenceId(runId, e.ref), "Legacy evidence belongs to another run or class") }
            val unverified = stringList(review, "unverified")
            if (scenario == "bootstrap") {
                requireInput(entry.semanticId == Digests.text("semantic\n${artifact.sha256}\n${entry.binding.descriptor}"), "Legacy Bootstrap semantic identity mismatch")
                requireInput(review["name"].asString == entry.name && review["rationale"].asString == entry.rationale && entry.rationale.isNotBlank(), "Legacy naming rationale mismatch")
                val expectedProposal = Digests.text("proposal\n${artifact.sha256}\n${entry.binding.descriptor}\n${JsonFiles.encode(entry.captures.toSortedMap())}")
                requireInput(d["proposalId"]?.asString == expectedProposal, "Legacy Bootstrap proposal differs from captures")
                review["proposalId"]?.let { requireInput(it.asString == expectedProposal, "Legacy review proposal mismatch") }
                val threshold = Confidence.valueOf(report.getAsJsonObject("profile")["minConfidence"]?.asString ?: throw ValidationException("Missing original Bootstrap confidence threshold"))
                requireInput(level.ordinal <= threshold.ordinal && evidence.values.all { it.ref.apkSha256 == artifact.sha256 }, "Legacy Bootstrap threshold/APK mismatch")
                requireInput(evidence.keys == ids.toSet(), "Legacy Bootstrap evidence differs from review")
            } else {
                // v0.2 migration reports did not persist their configurable threshold.
                // HIGH satisfies every supported threshold; weaker reviews need the missing policy proof.
                requireInput(level == Confidence.HIGH, "Legacy migration report lacks threshold proof for a non-HIGH review")
                requireInput(parse(d, "target", ClassRef::class.java) == entry.binding && review["targetDescriptor"].asString == entry.binding.descriptor,
                    "Legacy migration target differs from knowledge")
                requireInput(d["revisionId"]?.asString == revision && review["nameStillApplies"].asBoolean && review["identityReason"].asString == entry.rationale && entry.rationale.isNotBlank(), "Legacy continuity review incomplete")
                validateMigrationTask(report, taskId, entry, review, evidence, ids)
            }
            requireInput(evidence.values.none { it.incomplete } || unverified.any { it.isNotBlank() }, "Legacy incomplete evidence lacks original acknowledgment")
        }
        LegacyUpgrade.verifyTiny(source.resolve("mapping.tiny"), knowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        createNewDirectory(out)
        val result = LegacyUpgrade.publish(artifact, knowledge.entries, knowledge.unresolved, source, out, oldId, "v02-import:$oldId", execute)
        inputArtifacts.forEach(Digests::verify)
        JsonFiles.writeNew(out.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "v02-import-report", "knowledgeId" to result.knowledge.knowledgeId,
            "parentKnowledgeId" to oldId, "sourceKnowledge" to Digests.artifact(knowledgePath), "legacyReport" to report,
            "decisions" to result.decisions, "accepted" to result.knowledge.entries.size, "unresolved" to result.knowledge.unresolved.size))
        result.knowledge
    }

    private fun validateMigrationTask(report: JsonObject, taskId: String, entry: KnowledgeEntry, review: JsonObject,
                                      evidence: Map<String, KnowledgeEvidence>, ids: List<String>) {
        val task = report.getAsJsonArray("tasks").map { it.asJsonObject }.singleOrNull { it["taskId"].asString == taskId }
            ?: throw ValidationException("Legacy migration task missing")
        val sourceEntry = parse(task, "entry", KnowledgeEntry::class.java)
        requireInput(sourceEntry.semanticId == entry.semanticId && sourceEntry.name == entry.name && sourceEntry.locators == entry.locators && sourceEntry.captures == entry.captures, "Legacy migrated entry changed its source semantics or rules")
        val source = sourceEntry.binding
        val sourceArtifact = parse(report, "sourceApk", Artifact::class.java)
        requireInput(source.apkSha256 == sourceArtifact.sha256 && evidence.values.any { it.ref == source }, "Legacy migration source evidence missing")
        val candidates = task.getAsJsonArray("candidates").map { it.asJsonObject }
        val refs = candidates.map { parse(it, "ref", ClassRef::class.java) }
        requireInput(refs.distinct().size == refs.size && refs.all { it.apkSha256 == entry.binding.apkSha256 }, "Invalid legacy candidate identities")
        requireInput(candidates.any { parse(it, "ref", ClassRef::class.java) == entry.binding && it["status"].asString == "PASS" }, "Legacy selected target lacked a passing candidate")
        val comparisons = review.getAsJsonArray("candidateComparisons")?.map { it.asJsonObject }.orEmpty()
        if (refs.size > 1) requireInput(comparisons.map { it["targetDescriptor"].asString }.toSet() == refs.map { it.descriptor }.toSet(), "Legacy comparison was incomplete")
        requireInput(comparisons.map { it["targetDescriptor"].asString }.distinct().size == comparisons.size, "Duplicate legacy comparison")
        if (comparisons.isNotEmpty()) requireInput(comparisons.count { it["disposition"].asString == "SELECT" } == 1, "Legacy comparison has no unique selected record")
        val allIds = ids.toMutableSet()
        for (comparison in comparisons) {
            val descriptor = comparison["targetDescriptor"].asString
            val candidate = refs.singleOrNull { it.descriptor == descriptor } ?: throw ValidationException("Legacy comparison not a candidate")
            val disposition = comparison["disposition"].asString
            requireInput(disposition in setOf("SELECT", "EXCLUDE") && comparison["reason"].asString.isNotBlank(), "Legacy comparison was not resolved")
            requireInput((disposition == "SELECT") == (descriptor == entry.binding.descriptor), "Legacy comparison target mismatch")
            val references = stringList(comparison, "evidenceIds")
            requireInput(references.distinct().size == references.size && references.all { it in evidence } && references.any { evidence.getValue(it).ref == candidate }, "Legacy comparison evidence missing or foreign")
            allIds += references
        }
        requireInput(evidence.keys == allIds, "Legacy published evidence differs from review")
        requireInput(evidence.values.all { it.ref.apkSha256 in setOf(sourceArtifact.sha256, entry.binding.apkSha256) }, "Legacy evidence APK outside migration")
        for (key in listOf("sourceScan", "targetScan")) requireInput(report.getAsJsonObject(key).getAsJsonArray("diagnostics").size() == 0, "Legacy scan was incomplete")
    }

    private fun verifyEvidence(root: Path, e: KnowledgeEvidence) {
        requireInput(e.evidenceId.matches(Regex("[a-f0-9]{64}")) && e.javaPath == "evidence/${e.evidenceId}/code.java", "Invalid legacy evidence path")
        requireInput(Files.isRegularFile(root.resolve(e.javaPath)) && Digests.file(root.resolve(e.javaPath)) == e.javaSha256, "Legacy Java evidence missing or changed")
        if (e.smaliPath != null) requireInput(e.smaliPath == "evidence/${e.evidenceId}/code.smali" && Files.isRegularFile(root.resolve(e.smaliPath)) && Digests.file(root.resolve(e.smaliPath)) == e.smaliSha256, "Legacy Smali evidence missing or changed")
        else requireInput(e.smaliSha256 == null, "Legacy Smali hash without file")
        Identities.requireDescriptor(e.ref.descriptor)
    }
    private fun stringList(obj: JsonObject, key: String): List<String> = obj.getAsJsonArray(key)?.map { it.asString }
        ?: throw ValidationException("Missing legacy $key")
    private fun <T> parse(obj: JsonObject, key: String, type: Class<T>): T = JsonFiles.gson.fromJson(obj[key] ?: throw ValidationException("Missing legacy $key"), type)
}
