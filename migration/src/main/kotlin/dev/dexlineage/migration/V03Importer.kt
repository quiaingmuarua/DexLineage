package dev.dexlineage.migration

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.migration.legacy.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import dev.dexlineage.rules.RuleEngine
import java.nio.file.Files
import java.nio.file.Path

/** Explicit import of v0.3 packages. History paths are explicit inputs, never ambient directory scans. */
object V03Importer {
    fun importKnowledge(knowledgePath: Path, apkPath: Path, out: Path, historyPaths: List<Path> = emptyList()): VersionKnowledge =
        importWithExecutor(knowledgePath, apkPath, out, historyPaths, ResolutionEngine::execute)

    internal fun importWithExecutor(knowledgePath: Path, apkPath: Path, out: Path, historyPaths: List<Path> = emptyList(),
                                    execute: ResolutionExecutor): VersionKnowledge = checkedInput("v0.3 import") {
        val paths = (listOf(knowledgePath) + historyPaths).map { it.toAbsolutePath().normalize() }.distinct()
        val packages = paths.map(::readPackage)
        val primary = packages.first()
        val byId = packages.groupBy { it.knowledge.knowledgeId }
        requireInput(byId.values.all { group -> group.map { it.knowledge }.distinct().size == 1 && group.map { it.report }.distinct().size == 1 }, "Conflicting explicit history packages")
        val artifact = Digests.artifact(apkPath)
        requireInput(artifact.sha256 == primary.knowledge.artifact.sha256, "Provided APK differs from v0.3 knowledge")
        val reviewed = mutableSetOf<Pair<String, String>>()
        fun verifySemantic(pkg: Package, entry: V03Entry, visiting: Set<String>) {
            val key = pkg.knowledge.knowledgeId to entry.semanticId
            if (key in reviewed) return
            requireInput(pkg.knowledge.knowledgeId !in visiting, "Cyclic v0.3 history")
            val currentPrefix = "${pkg.scene}:${pkg.runId}:"
            if (entry.provenance.startsWith(currentPrefix)) verifyReview(pkg, entry)
            else {
                val parentId = pkg.knowledge.parentKnowledgeId ?: throw ValidationException("Inherited entry lacks a parent knowledge reference")
                val parent = byId[parentId]?.firstOrNull()
                    ?: throw ValidationException("Original Review is not in this package; provide explicit --history knowledge $parentId for ${entry.semanticId}")
                val prior = parent.knowledge.entries.singleOrNull { it.semanticId == entry.semanticId }
                    ?: throw ValidationException("Inherited entry is absent from declared parent knowledge")
                requireInput(prior == entry, "Inherited entry changed without an original Review")
                verifySemantic(parent, prior, visiting + pkg.knowledge.knowledgeId)
            }
            reviewed += key
        }
        primary.knowledge.entries.forEach { verifySemantic(primary, it, emptySet()) }
        createNewDirectory(out)
        // Preserve exact historical proof shapes separately; unresolved history is not a schema-4 proof.
        val historyDir = Files.createDirectories(out.resolve("legacy"))
        packages.distinctBy { it.knowledge.knowledgeId }.forEach { pkg ->
            val dir = Files.createDirectory(historyDir.resolve(pkg.knowledge.knowledgeId))
            listOf("knowledge.json", "report.json", "mapping.tiny").forEach { Files.copy(pkg.root.resolve(it), dir.resolve(it)) }
            (pkg.knowledge.entries + pkg.knowledge.unresolved.map { it.entry }).flatMap { it.evidence }
                .distinctBy { it.evidenceId }.forEach { dev.dexlineage.knowledge.KnowledgeFiles.copyEvidence(pkg.root, dir, it) }
        }
        val upgraded = LegacyUpgrade.publish(artifact, primary.knowledge.entries.map { it.historicalEntry() },
            primary.knowledge.unresolved.map { it.historical() }, primary.root, out, primary.knowledge.knowledgeId,
            "v03-import:${primary.knowledge.knowledgeId}", execute)
        packages.flatMap { it.artifacts }.forEach(Digests::verify)
        JsonFiles.writeNew(out.resolve("report.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "v03-import-report",
            "knowledgeId" to upgraded.knowledge.knowledgeId, "parentKnowledgeId" to primary.knowledge.knowledgeId,
            "sourceKnowledge" to Digests.artifact(knowledgePath), "historyKnowledgeIds" to packages.drop(1).map { it.knowledge.knowledgeId },
            "legacyArtifacts" to packages.flatMap { it.artifacts }, "decisions" to upgraded.decisions,
            "accepted" to upgraded.knowledge.entries.size, "unresolved" to upgraded.knowledge.unresolved.size))
        upgraded.knowledge
    }

    private data class Package(val root: Path, val knowledge: V03Knowledge, val report: JsonObject,
        val scene: String, val runId: String, val artifacts: List<Artifact>)

    private fun readPackage(path: Path): Package {
        val root = path.parent
        val raw = JsonParser.parseString(Files.readString(path)).asJsonObject
        val knowledge = JsonFiles.read(path, V03Knowledge::class.java, 3)
        requireInput(raw == JsonFiles.gson.toJsonTree(knowledge), "Unsupported or incomplete schema-3 knowledge fields")
        requireInput(knowledge.kind == "version-knowledge" && knowledge.knowledgeId == Digests.text(JsonFiles.encode(knowledge.copy(knowledgeId = ""))), "v0.3 knowledge fingerprint mismatch")
        val allIds = knowledge.entries.map { it.semanticId } + knowledge.unresolved.map { it.entry.semanticId }
        requireInput(allIds.distinct().size == allIds.size, "Duplicate v0.3 semantic identity")
        requireInput(knowledge.entries.map { it.binding }.distinct().size == knowledge.entries.size, "Duplicate v0.3 current binding")
        for (entry in knowledge.entries + knowledge.unresolved.map { it.entry }) {
            requireInput(entry.semanticId.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")), "Invalid v0.3 semantic ID")
            Identities.renamedFullName(entry.binding.descriptor, entry.name)
            requireInput(entry.locators.isNotEmpty(), "Missing historical locators")
            entry.locators.forEach(RuleEngine::validate)
            requireInput(entry.evidence.map { it.evidenceId }.distinct().size == entry.evidence.size, "Duplicate historical evidence")
            entry.evidence.forEach { verifyEvidence(root, it) }
        }
        knowledge.unresolved.forEach { requireInput(it.sourceKnowledgeId.isNotBlank() && it.reason.isNotBlank(), "Missing unresolved history source") }
        knowledge.entries.forEach { entry ->
            requireInput(entry.binding.apkSha256 == knowledge.artifact.sha256 && entry.evidence.any { it.ref == entry.binding }, "Current v0.3 entry lacks owner evidence or APK identity")
            val rule = entry.ruleRevision ?: throw ValidationException("Missing v0.3 rule revision")
            val proof = entry.resolution ?: throw ValidationException("Missing v0.3 matching proof")
            verifyResolution(proof)
            requireInput(rule == proof.rule && rule.locators == entry.locators && proof.status == ResolutionStatus.UNIQUE && proof.candidates.single().ref == entry.binding, "Historical binding was not uniquely resolved")
        }
        LegacyUpgrade.verifyTiny(root.resolve("mapping.tiny"), knowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) })
        val report = JsonParser.parseString(Files.readString(root.resolve("report.json"))).asJsonObject
        requireInput(report["schemaVersion"]?.asInt == 3 && report["knowledgeId"]?.asString == knowledge.knowledgeId, "v0.3 report identity mismatch")
        val scene = when (report["kind"]?.asString) {
            "analysis-report" -> "analysis"
            "migration-report" -> "migration"
            else -> throw ValidationException("v0.3 import needs an Analysis/Migration publication; re-import original S1/v0.2 inputs through their explicit adapter")
        }
        val runId = report["runId"].asString
        requireInput(knowledge.provenance == "$scene:$runId", "v0.3 publication provenance mismatch")
        requireInput(parse(report, if (scene == "analysis") "apk" else "targetApk", Artifact::class.java) == knowledge.artifact, "v0.3 report APK mismatch")
        requireInput(report[if (scene == "analysis") "confirmed" else "accepted"]?.asInt == knowledge.entries.size && report["unresolved"]?.asInt == knowledge.unresolved.size, "v0.3 report totals differ from knowledge")
        val scanKeys = if (scene == "analysis") listOf("scan") else listOf("sourceScan", "targetScan")
        scanKeys.forEach { requireInput(report.getAsJsonObject(it).getAsJsonArray("diagnostics").size() == 0, "Historical scan was incomplete") }
        val decisions = report.getAsJsonArray("decisions").map { it.asJsonObject }
        requireInput(decisions.map { it["taskId"].asString }.distinct().size == decisions.size, "Duplicate historical decision")
        requireInput(decisions.all { it["state"].asString in TaskState.entries.map { state -> state.name } }, "Invalid historical decision state")
        val tasks = report.getAsJsonArray("tasks").map { it.asJsonObject }
        requireInput(tasks.map { it["taskId"].asString }.toSet() == decisions.map { it["taskId"].asString }.toSet() && tasks.map { it["taskId"].asString }.distinct().size == tasks.size, "Historical task/decision set mismatch")
        decisions.filter { it["state"].asString == "ACCEPTED" }.forEach { decision ->
            val semanticId = if (scene == "analysis") decision["semanticId"].asString else decision["taskId"].asString
            requireInput(knowledge.entries.any { it.semanticId == semanticId }, "Accepted historical decision has no published entry")
        }
        return Package(root, knowledge, report, scene, runId,
            listOf(path, root.resolve("report.json"), root.resolve("mapping.tiny")).map(Digests::artifact))
    }

    private fun verifyReview(pkg: Package, entry: V03Entry) {
        val decisions = pkg.report.getAsJsonArray("decisions").map { it.asJsonObject }
        val decision = decisions.singleOrNull { it["state"].asString == "ACCEPTED" &&
            (if (pkg.scene == "analysis") it["semanticId"]?.asString else it["taskId"]?.asString) == entry.semanticId }
            ?: throw ValidationException("Entry has no original accepted Review: ${entry.semanticId}")
        val taskId = decision["taskId"].asString
        val review = decision.getAsJsonObject("review") ?: throw ValidationException("Missing original semantic Review")
        requireInput(review["taskId"]?.asString == taskId && review["action"]?.asString == "ACCEPT", "Historical Review task/action mismatch")
        requireInput(review["level"]?.asString == "HIGH", "Historical report lacks policy proof for non-HIGH Review")
        val proof = entry.resolution!!
        requireInput(review["resolutionId"]?.asString == proof.resolutionId && review["ruleRevisionId"]?.asString == proof.rule.revisionId, "Historical Review used another matching proof")
        val supersedes = review["supersedes"]?.takeUnless { it.isJsonNull }?.asString
        val record = StoredReview(schemaVersion = 3, revisionId = "", runId = pkg.runId, taskId = taskId, supersedes = supersedes, payload = review)
        val revision = Digests.text(JsonFiles.encode(record))
        requireInput(pkg.report.getAsJsonObject("reviewRevisions")[taskId]?.asString == revision && entry.provenance == "${pkg.scene}:${pkg.runId}:$revision", "Historical Review revision mismatch")
        requireInput(decision["name"]?.asString == entry.name && parse(decision, "target", ClassRef::class.java) == entry.binding, "Historical Review output differs from entry")
        val ids = strings(review, "evidenceIds")
        requireInput(ids.distinct().size == ids.size && ids.toSet() == entry.evidence.map { it.evidenceId }.toSet(), "Historical Review evidence set differs from published evidence")
        entry.evidence.forEach { requireInput(it.evidenceId == Identities.evidenceId(pkg.runId, it.ref), "Historical evidence has another run identity") }
        val task = pkg.report.getAsJsonArray("tasks").map { it.asJsonObject }.single { it["taskId"].asString == taskId }
        requireInput(parse(task, "resolution", V03Resolution::class.java) == proof, "Historical task proof differs from entry")
        if (pkg.scene == "analysis") {
            requireInput(review["name"]?.asString == entry.name && review["rationale"]?.asString == entry.rationale && entry.rationale.isNotBlank(), "Historical naming rationale mismatch")
            requireInput(entry.evidence.all { it.ref.apkSha256 == pkg.knowledge.artifact.sha256 }, "Analysis Review contains another APK")
            proof.matches.filter { it.owner == entry.binding && it.status == MatchStatus.PASS }.mapNotNull { it.field?.call?.declaringType }.distinct().forEach { factory ->
                requireInput(entry.evidence.any { it.ref.apkSha256 == entry.binding.apkSha256 && it.ref.descriptor == factory }, "Historical factory evidence missing")
            }
        } else {
            requireInput(review["nameStillApplies"]?.asBoolean == true && review["identityReason"]?.asString == entry.rationale && entry.rationale.isNotBlank(), "Historical continuity rationale mismatch")
            val source = parse(task, "entry", V03Entry::class.java)
            val sourceApk = parse(pkg.report, "sourceApk", Artifact::class.java)
            requireInput(source.semanticId == entry.semanticId && source.name == entry.name && source.binding.apkSha256 == sourceApk.sha256, "Historical source semantics differ")
            requireInput(entry.evidence.any { it.ref == source.binding }, "Historical source evidence missing")
            requireInput(entry.evidence.all { it.ref.apkSha256 in setOf(sourceApk.sha256, entry.binding.apkSha256) }, "Historical migration evidence has unrelated APK")
        }
        requireInput(entry.evidence.none { it.incomplete } || strings(review, "unverified").any { it.isNotBlank() }, "Historical partial code lacks Review acknowledgment")
    }

    private fun verifyResolution(proof: V03Resolution) {
        val rule = proof.rule
        requireInput(rule.locators.isNotEmpty() && rule.locators == rule.locators.distinct() && rule.revisionId == Digests.text(JsonFiles.encode(rule.locators)), "v0.3 rule digest mismatch")
        requireInput(proof.schemaVersion == 3 && proof.engineVersion == "0.3.0" && proof.engineBuildId.isNotBlank() && proof.searchScope == "apk-all-dex", "Unsupported historical matching engine")
        requireInput(proof.resolutionId == Digests.text(JsonFiles.encode(proof.copy(resolutionId = ""))), "v0.3 Resolution digest mismatch")
        val sorted = proof.matches.sortedWith(compareBy({ it.locatorIndex }, { it.owner.descriptor }, { it.field?.fieldName.orEmpty() }, { it.field?.fieldType.orEmpty() }))
        requireInput(sorted == proof.matches, "Historical facts are not canonical")
        proof.matches.forEach { fact ->
            Identities.requireDescriptor(fact.owner.descriptor)
            requireInput(fact.owner.apkSha256 == proof.apkSha256 && fact.locatorIndex in rule.locators.indices && fact.factors.isNotEmpty(), "Historical fact identity mismatch")
            val status = if (fact.factors.any { it.status == MatchStatus.FAIL }) MatchStatus.FAIL else if (fact.factors.any { it.status == MatchStatus.UNKNOWN }) MatchStatus.UNKNOWN else MatchStatus.PASS
            requireInput(fact.status == status && (fact.field == null || fact.field.owner == fact.owner), "Historical condition/field mismatch")
        }
        val candidates = sorted.filter { it.status != MatchStatus.FAIL }.groupBy { it.owner.descriptor }.toSortedMap().map { (_, facts) ->
            requireInput(facts.map { it.owner }.distinct().size == 1, "Conflicting historical original identity")
            V03Candidate(facts.first().owner, if (facts.any { it.status == MatchStatus.PASS }) MatchStatus.PASS else MatchStatus.UNKNOWN, facts)
        }
        val pass = candidates.count { it.status == MatchStatus.PASS }
        val state = when { pass >= 2 -> ResolutionStatus.AMBIGUOUS; candidates.isEmpty() -> ResolutionStatus.NO_MATCH; candidates.size == 1 && pass == 1 -> ResolutionStatus.UNIQUE; else -> ResolutionStatus.UNKNOWN }
        requireInput(candidates == proof.candidates && state == proof.status, "Historical candidate/uniqueness result mismatch")
    }

    private fun verifyEvidence(root: Path, evidence: KnowledgeEvidence) {
        requireInput(evidence.evidenceId.matches(Regex("[a-f0-9]{64}")) && evidence.javaPath == "evidence/${evidence.evidenceId}/code.java", "Invalid historical evidence path")
        requireInput(Files.isRegularFile(root.resolve(evidence.javaPath)) && Digests.file(root.resolve(evidence.javaPath)) == evidence.javaSha256, "Historical Java evidence missing or changed")
        if (evidence.smaliPath != null) requireInput(evidence.smaliPath == "evidence/${evidence.evidenceId}/code.smali" && Files.isRegularFile(root.resolve(evidence.smaliPath)) && Digests.file(root.resolve(evidence.smaliPath)) == evidence.smaliSha256, "Historical Smali evidence missing or changed")
        else requireInput(evidence.smaliSha256 == null, "Historical Smali hash without file")
    }
    private fun strings(obj: JsonObject, key: String): List<String> = obj.getAsJsonArray(key)?.map { it.asString } ?: throw ValidationException("Missing historical $key")
    private fun <T> parse(obj: JsonObject, key: String, type: Class<T>): T = JsonFiles.gson.fromJson(obj[key] ?: throw ValidationException("Missing historical $key"), type)
}
