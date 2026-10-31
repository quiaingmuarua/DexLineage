package dev.dexlineage.cli

import com.google.gson.JsonParser
import com.google.gson.JsonObject
import dev.dexlineage.analysis.*
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.migration.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import java.util.UUID
import kotlin.test.*

/** Explicit private acceptance. Saved matching answers are assertions, never inputs to fresh matching. */
object V04CaseAcceptance {
    private data class RoundPath(val run: String = "", val output: String = "")
    private data class PublishedRuleRequirement(val strategyId: String = "", val parameters: JsonObject = JsonObject(), val minimum: Int = 1)
    private data class PreservedInputs(val schemaVersion: Int = SCHEMA_VERSION, val artifacts: List<Artifact> = emptyList())
    private data class Manifest(
        val schemaVersion: Int = SCHEMA_VERSION,
        val corpus: String = "",
        val analysisSeeds: List<RoundPath> = emptyList(),
        val analysisRounds: List<RoundPath> = emptyList(),
        val migrationRounds: List<RoundPath> = emptyList(),
        val shapeRounds: List<RoundPath> = emptyList(),
        val upgradedV03: List<String> = emptyList(),
        val expectedAnnotationCounts: Map<String, Int> = emptyMap(),
        val expectedClassTargets: Int? = null,
        val requiredStrategyIds: List<String> = emptyList(),
        val requiredPublishedRules: List<PublishedRuleRequirement> = emptyList(),
        val selectedCorpusTargets: List<String> = emptyList(),
        val controlKnowledge: String? = null,
        val controlNames: List<String> = emptyList(),
        val preservedArtifactsFile: String? = null,
    )
    private data class CheckedRound(val runId: String, val apk: Artifact, val output: Path, val knowledge: VersionKnowledge)

    fun run(config: Path) {
        val configRoot = config.toAbsolutePath().normalize().parent
        val properties = Properties().apply { Files.newBufferedReader(config).use(::load) }
        fun configured(key: String): Path = configRoot.resolve(requireNotNull(properties.getProperty(key)) { "Missing $key" }).normalize()
        val manifestPath = configured("caseManifest")
        val manifest = JsonFiles.read(manifestPath, Manifest::class.java)
        val root = manifestPath.parent
        fun resolve(value: String): Path {
            require(value.isNotBlank()) { "Empty case manifest path" }
            return root.resolve(value).normalize()
        }
        require(manifest.analysisRounds.isNotEmpty() && manifest.migrationRounds.isNotEmpty()) { "Acceptance requires source and migration rounds" }
        val out = configured("acceptanceRoot").resolve(UUID.randomUUID().toString())
        Files.createDirectories(out)
        val inputArtifacts = linkedMapOf<String, Artifact>()
        fun remember(artifact: Artifact) {
            val previous = inputArtifacts.putIfAbsent(artifact.path, artifact)
            assertTrue(previous == null || previous == artifact, "One input path has conflicting frozen hashes")
            Digests.verify(artifact)
        }
        remember(Digests.artifact(config)); remember(Digests.artifact(manifestPath))
        val corpusPath = resolve(manifest.corpus)
        val corpus = ManualCorpusFiles.read(corpusPath)
        remember(Digests.artifact(corpusPath)); remember(corpus.apk); remember(corpus.project)
        val selectedTargets = manifest.selectedCorpusTargets.toSet()
        require(selectedTargets.size == manifest.selectedCorpusTargets.size && selectedTargets.all { id -> corpus.targets.any { it.targetId == id } }) {
            "Slice targets must be distinct original corpus targets"
        }
        manifest.preservedArtifactsFile?.let { value ->
            val file = resolve(value)
            remember(Digests.artifact(file))
            val preserved = JsonFiles.read(file, PreservedInputs::class.java)
            require(preserved.schemaVersion == SCHEMA_VERSION && preserved.artifacts.isNotEmpty()) { "Invalid preserved-input snapshot" }
            preserved.artifacts.forEach(::remember)
        }
        if (manifest.expectedAnnotationCounts.isNotEmpty()) assertEquals(manifest.expectedAnnotationCounts, corpus.annotationCounts)
        manifest.expectedClassTargets?.let { assertEquals(it, corpus.targets.size) }
        val imported = AnalysisService.importJadx(Path.of(corpus.apk.path), Path.of(corpus.project.path), out.resolve("fresh-corpus"))
        assertEquals(corpus, imported, "Fresh corpus import must preserve every original annotation and target")

        val checkedAnchorProofs = mutableSetOf<String>()
        val matchingRecords = mutableListOf<Map<String, Any>>()
        val replayRecords = mutableListOf<Map<String, Any>>()
        fun anchorIdentity(anchor: SupportAnchor) = "${anchor.binding.owner.apkSha256}:${anchor.key}:${anchor.resolution.resolutionId}"

        fun available(base: VersionKnowledge?, definitions: Map<String, RuleRevision>, apk: Artifact, buildId: String): Map<String, SupportAnchor> {
            val anchors = base?.anchors.orEmpty().filter { it.rule == definitions[it.key] && it.resolution.engineBuildId == buildId }
                .associateBy { it.key }.toMutableMap()
            while (true) {
                val stale = anchors.filter { (_, anchor) ->
                    anchor.rule.requires.values.any { it !in anchors } ||
                        anchor.resolution.dependencies != anchor.rule.requires.mapValues { (_, key) -> anchors.getValue(key) }
                }.keys
                if (stale.isEmpty()) break
                stale.forEach(anchors::remove)
            }
            anchors.values.forEach { anchor ->
                assertEquals(apk.sha256, anchor.binding.owner.apkSha256, "Source-version anchor cannot serve as a target dependency")
                assertTrue(anchorIdentity(anchor) in checkedAnchorProofs,
                    "Manifest omitted an earlier producer round for anchor ${anchor.key}; a saved candidate alone is not fresh proof")
            }
            return anchors
        }

        fun checkMatching(label: String, apk: Artifact, buildId: String, inventory: Map<String, String>,
                          rules: List<RuleRevision>, saved: List<Resolution>, waiting: Map<String, List<String>>,
                          anchors: Map<String, SupportAnchor>, anchorTasks: List<Pair<String, Resolution?>>) {
            assertEquals(ResolutionEngine.buildId(), buildId, "The case must be prepared with this matching implementation")
            val grouped = saved.groupBy { it.rule.revisionId }
            assertTrue(grouped.values.all { it.distinct().size == 1 }, "One frozen rule has conflicting saved results")
            val expected = grouped.mapValues { it.value.first() }
            // Only APK, executable rules and independently checked upstream anchors enter the engine.
            val fresh = ResolutionEngine.execute(apk, rules, out.resolve("$label-matching"), anchors)
            JsonFiles.writeNew(out.resolve("$label-matching.json"), mapOf("schemaVersion" to SCHEMA_VERSION,
                "apk" to apk, "rules" to rules.distinctBy { it.revisionId }, "scan" to fresh.scan.stats,
                "resolutions" to fresh.resolutions, "waiting" to fresh.waiting))
            assertTrue(fresh.scan.stats.diagnostics.isEmpty(), "Fresh scan must be complete")
            assertEquals(inventory, fresh.scan.classes, "Fresh raw class inventory differs")
            assertEquals(waiting, fresh.waiting, "Dependency waiting must not become a fabricated NO_MATCH")
            assertEquals(expected, fresh.resolutions, "Fresh APK matching differs from saved Resolutions: $label")
            anchorTasks.forEach { (key, proof) ->
                if (proof?.status == ResolutionStatus.UNIQUE) {
                    assertEquals(proof, fresh.resolutions[proof.rule.revisionId])
                    checkedAnchorProofs += "${apk.sha256}:$key:${proof.resolutionId}"
                }
            }
            matchingRecords += mapOf("label" to label, "apkSha256" to apk.sha256, "rules" to rules.distinctBy { it.revisionId }.size,
                "executed" to fresh.resolutions.size, "waiting" to fresh.waiting.size,
                "resolutionCounts" to fresh.resolutions.values.groupingBy { it.status }.eachCount(),
                "strategyCounts" to rules.distinctBy { it.revisionId }.groupingBy { it.strategyId }.eachCount(),
                "scanMillis" to fresh.scan.stats.elapsedMillis, "analysisMillis" to (fresh.analysis?.elapsedMillis ?: 0))
        }

        fun checkPackage(directory: Path, knowledge: VersionKnowledge) {
            knowledge.entries.forEach { entry ->
                assertEquals(knowledge.artifact.sha256, entry.binding.apkSha256)
                assertEquals(entry.binding, entry.resolution!!.uniqueRef)
                assertEquals(ResolutionStatus.UNIQUE, entry.resolution!!.status)
            }
            knowledge.anchors.forEach { anchor ->
                RuleProofs.validateAnchor(anchor, knowledge.artifact.sha256)
                assertTrue(anchorIdentity(anchor) in checkedAnchorProofs, "Published anchor lacks a freshly checked producer")
            }
            val lines = Files.readAllLines(directory.resolve("mapping.tiny"))
            assertEquals("tiny\t2\t0\tobfuscated\tnamed", lines.firstOrNull())
            val actual = lines.drop(1).filter(String::isNotEmpty).map { line ->
                val columns = line.split('\t')
                assertEquals(3, columns.size)
                assertEquals("c", columns[0], "Auxiliary method anchors and member renames must not enter Tiny")
                "L${columns[1]};" to columns[2].replace('/', '.')
            }
            assertEquals(knowledge.entries.size, actual.size, "Mapping must contain exactly confirmed class entries")
            assertEquals(actual.size, actual.map { it.first }.distinct().size)
            assertEquals(knowledge.entries.associate { it.binding.descriptor to Identities.renamedFullName(it.binding.descriptor, it.name) }, actual.toMap())
        }

        fun replay(label: String, directory: Path, publication: Path, analysis: Boolean, knowledge: VersionKnowledge) {
            val replay = out.resolve("$label-publication")
            if (analysis) AnalysisService.publish(directory, replay, publication.resolve("report.json"))
            else MigrationService.publish(directory, replay, publication.resolve("report.json"))
            for (file in listOf("knowledge.json", "mapping.tiny")) assertEquals(Files.readString(publication.resolve(file)), Files.readString(replay.resolve(file)), "Saved publication replay differs: $label/$file")
            checkPackage(replay, KnowledgeFiles.read(replay.resolve("knowledge.json")))
            replayRecords += mapOf("label" to label, "knowledgeId" to knowledge.knowledgeId, "confirmed" to knowledge.entries.size,
                "anchors" to knowledge.anchors.size, "unresolved" to knowledge.unresolved.size, "identical" to true)
        }

        fun analysisRound(location: RoundPath, label: String, main: Boolean): CheckedRound {
            val dir = resolve(location.run)
            val publication = resolve(location.output)
            val run = AnalysisService.readRun(dir)
            val knowledge = KnowledgeFiles.read(publication.resolve("knowledge.json"))
            remember(run.apk); remember(run.rulesFile)
            listOfNotNull(run.baseFile, run.discoveryFile, run.corpusFile).forEach(::remember)
            run.discovery?.let { remember(it.profileSource) }
            assertEquals(run.apk.sha256, knowledge.artifact.sha256)
            if (main) {
                assertEquals(corpus.corpusId, run.corpus?.corpusId, "Main rounds must retain the complete manual corpus")
                if (selectedTargets.isNotEmpty()) {
                    assertEquals(selectedTargets, run.tasks.map { it.request.corpusTargetId }.toSet(), "Slice changed its selected corpus targets")
                    assertEquals(selectedTargets.size, run.tasks.size)
                }
                val report = JsonParser.parseString(Files.readString(publication.resolve("report.json"))).asJsonObject
                val targets = report.getAsJsonArray("corpusTargets")
                assertEquals(corpus.targets.size, targets.size(), "Publication omitted unconfigured corpus targets")
                assertEquals(corpus.targets.map { it.targetId }.toSet(), targets.map { it.asJsonObject.getAsJsonObject("target")["targetId"].asString }.toSet())
            }
            val definitions = run.anchorTasks.associate { it.key to it.rule }
            val frozenAnchors = available(run.baseKnowledge, definitions, run.apk, run.engineBuildId)
            val proofs = run.tasks.mapNotNull { it.resolution } + run.anchorTasks.mapNotNull { it.resolution }
            val waiting = (run.tasks.filter { it.resolution == null }.map { it.rule.revisionId to it.waitingFor } +
                run.anchorTasks.filter { it.resolution == null }.map { it.rule.revisionId to it.waitingFor }).toMap()
            checkMatching(label, run.apk, run.engineBuildId, run.classInventory, run.tasks.map { it.rule } + definitions.values,
                proofs, waiting, frozenAnchors, run.anchorTasks.map { it.key to it.resolution })
            run.tasks.filter { it.expectedOwner != null && it.resolution?.status == ResolutionStatus.UNIQUE && it.resolution!!.uniqueRef != it.expectedOwner }
                .forEach { task -> assertTrue(knowledge.entries.none { it.resolution?.resolutionId == task.resolution!!.resolutionId }, "Manual owner mismatch was published") }
            checkPackage(publication, knowledge)
            replay(label, dir, publication, true, knowledge)
            return CheckedRound(run.runId, run.apk, publication, knowledge)
        }

        manifest.analysisSeeds.forEachIndexed { index, location -> analysisRound(location, "analysis-seed-${index + 1}", false) }
        val sourceRounds = manifest.analysisRounds.mapIndexed { index, location -> analysisRound(location, "analysis-${index + 1}", true) }
        val source = sourceRounds.last()
        assertTrue(source.knowledge.entries.isNotEmpty(), "Source acceptance cannot be an empty Mapping")
        val controlChecks = manifest.controlKnowledge?.let { value ->
            val file = resolve(value)
            remember(Digests.artifact(file))
            val baseline = KnowledgeFiles.read(file)
            assertEquals(source.apk.sha256, baseline.artifact.sha256)
            manifest.controlNames.map { name ->
                val old = baseline.entries.single { it.name == name }
                val current = source.knowledge.entries.single { it.name == name }
                assertEquals(old.semanticId, current.semanticId, "An existing control must keep its semantic identity")
                assertEquals(old.binding, current.binding)
                mapOf("name" to name, "semanticId" to current.semanticId, "sameBinding" to true, "countedAsNew" to false)
            }
        }.orEmpty()
        require(manifest.controlNames.isEmpty() || manifest.controlKnowledge != null) { "Control names require a baseline knowledge package" }

        fun migrationRound(location: RoundPath, label: String): CheckedRound {
            val dir = resolve(location.run)
            val publication = resolve(location.output)
            val run = MigrationService.readRun(dir)
            val knowledge = KnowledgeFiles.read(publication.resolve("knowledge.json"))
            listOf(run.sourceApk, run.targetApk, run.knowledgeFile).forEach(::remember)
            listOfNotNull(run.rulesFile, run.targetBaseFile).forEach(::remember)
            assertEquals(source.knowledge, run.knowledge, "Migration must consume the exact final source knowledge")
            assertEquals(Digests.file(source.output.resolve("knowledge.json")), run.knowledgeFile.sha256)
            assertEquals(source.knowledge.entries.map { it.semanticId }.toSet(), run.tasks.map { it.taskId }.toSet(), "Frozen semantic target set changed")
            assertEquals(source.knowledge.knowledgeId, knowledge.migrationSourceKnowledgeId)
            run.targetBase?.let { base ->
                assertEquals(run.targetApk.sha256, base.artifact.sha256)
                assertEquals(source.knowledge.knowledgeId, base.migrationSourceKnowledgeId)
                base.entries.forEach { old -> assertEquals(old.binding, knowledge.entries.single { it.semanticId == old.semanticId }.binding, "Target progress lost or moved an existing binding") }
            }
            val definitions = run.anchorTasks.associate { it.key to it.rule }
            val frozenAnchors = available(run.targetBase, definitions, run.targetApk, run.engineBuildId)
            val proofs = run.tasks.mapNotNull { it.resolution } + run.anchorTasks.mapNotNull { it.resolution }
            val waiting = (run.tasks.filter { it.resolution == null }.map { it.rule.revisionId to it.waitingFor } +
                run.anchorTasks.filter { it.resolution == null }.map { it.rule.revisionId to it.waitingFor }).toMap()
            checkMatching(label, run.targetApk, run.engineBuildId, run.targetInventory, run.tasks.map { it.rule } + definitions.values,
                proofs, waiting, frozenAnchors, run.anchorTasks.map { it.key to it.resolution })
            val sourceIds = (source.knowledge.entries.map { it.semanticId } + source.knowledge.unresolved.map { it.entry.semanticId }).toSet()
            assertEquals(sourceIds, (knowledge.entries.map { it.semanticId } + knowledge.unresolved.map { it.entry.semanticId }).toSet(), "Migration lost source knowledge")
            knowledge.unresolved.forEach { pending ->
                val original = source.knowledge.entries.singleOrNull { it.semanticId == pending.entry.semanticId }
                if (original != null) {
                    assertEquals(original, pending.entry)
                    assertEquals(source.knowledge.knowledgeId, pending.sourceKnowledgeId)
                    assertEquals(run.sourceApk.sha256, pending.entry.binding.apkSha256)
                } else assertEquals(source.knowledge.unresolved.single { it.entry.semanticId == pending.entry.semanticId }, pending)
            }
            checkPackage(publication, knowledge)
            replay(label, dir, publication, false, knowledge)
            return CheckedRound(run.runId, run.targetApk, publication, knowledge)
        }

        val migrations = manifest.migrationRounds.mapIndexed { index, location -> migrationRound(location, "migration-${index + 1}") }
        val target = migrations.last()
        assertTrue(target.knowledge.entries.isNotEmpty(), "Migration acceptance cannot be an empty Mapping")
        val shapes = manifest.shapeRounds.mapIndexed { index, location ->
            val kind = JsonParser.parseString(Files.readString(resolve(location.run).resolve("run.json"))).asJsonObject["kind"].asString
            when (kind) {
                "analysis-run" -> analysisRound(location, "shape-${index + 1}", false)
                "migration-run" -> migrationRound(location, "shape-${index + 1}")
                else -> error("Unsupported shape run: $kind")
            }
        }
        fun strategyCounts(value: VersionKnowledge): Map<String, Int> =
            (value.entries.map { it.ruleRevision!!.strategyId } + value.anchors.map { it.rule.strategyId }).groupingBy { it }.eachCount()
        for (checked in listOf(source, target)) assertTrue(strategyCounts(checked.knowledge).keys.containsAll(manifest.requiredStrategyIds),
            "Confirmed classes and resolved anchors do not cover configured strategy families")
        val publishedRuleChecks = manifest.requiredPublishedRules.map { requirement ->
            require(requirement.strategyId.isNotBlank() && requirement.minimum > 0) { "Invalid requiredPublishedRules item" }
            fun count(value: VersionKnowledge) = value.entries.count { entry ->
                val rule = entry.ruleRevision!!
                rule.strategyId == requirement.strategyId && requirement.parameters.entrySet().all { (key, expected) -> rule.parameters[key] == expected }
            }
            val sourceCount = count(source.knowledge)
            val targetCount = count(target.knowledge)
            assertTrue(sourceCount >= requirement.minimum, "Source lacks a required published rule: ${requirement.strategyId} ${requirement.parameters}")
            assertTrue(targetCount >= requirement.minimum, "Target lacks a required published rule: ${requirement.strategyId} ${requirement.parameters}")
            mapOf("strategyId" to requirement.strategyId, "parameters" to requirement.parameters,
                "minimum" to requirement.minimum, "sourcePublished" to sourceCount, "targetPublished" to targetCount)
        }

        fun readback(value: VersionKnowledge, directory: Path, label: String): List<VerifiedRename> {
            remember(value.artifact)
            val names = MappingOutput.verify(Path.of(value.artifact.path), directory.resolve("mapping.tiny"),
                value.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) }, out.resolve(label))
            assertEquals(value.entries.size, names.size)
            names.forEach { assertEquals(Identities.rawName(it.descriptor), it.rawName, "Readback changed the original identity") }
            return names
        }
        val sourceReadback = readback(source.knowledge, source.output, "source-readback")
        val targetReadback = readback(target.knowledge, target.output, "target-readback")
        val extraReadbacks = shapes.groupBy { it.apk.sha256 }.values.mapIndexed { index, rounds ->
            val final = rounds.last()
            mapOf("apkSha256" to final.apk.sha256, "confirmed" to final.knowledge.entries.size,
                "unresolved" to final.knowledge.unresolved.size,
                "readback" to readback(final.knowledge, final.output, "extra-$index-readback"))
        }
        val upgrades = manifest.upgradedV03.mapIndexed { index, value ->
            val configuredPath = resolve(value)
            val path = if (Files.isDirectory(configuredPath)) configuredPath.resolve("knowledge.json") else configuredPath
            val knowledge = KnowledgeFiles.read(path)
            remember(Digests.artifact(path))
            assertTrue(knowledge.provenance.startsWith("v03-import:"), "Configured upgrade is not an explicit v0.3 import")
            mapOf("knowledgeId" to knowledge.knowledgeId, "confirmed" to knowledge.entries.size, "unresolved" to knowledge.unresolved.size,
                "readback" to readback(knowledge, path.parent, "v03-upgrade-$index-readback"))
        }
        inputArtifacts.values.forEach(Digests::verify)
        JsonFiles.writeNew(out.resolve("acceptance.json"), mapOf("schemaVersion" to SCHEMA_VERSION, "kind" to "v04-real-case-acceptance",
            "caseManifest" to Digests.artifact(manifestPath), "corpusId" to corpus.corpusId, "annotationCounts" to corpus.annotationCounts,
            "classTargets" to corpus.targets.size, "matching" to matchingRecords, "publicationReplays" to replayRecords,
            "selectedCorpusTargets" to manifest.selectedCorpusTargets, "controlChecks" to controlChecks,
            "sourceConfirmed" to source.knowledge.entries.size, "sourceAnchors" to source.knowledge.anchors.size,
            "targetConfirmed" to target.knowledge.entries.size, "targetAnchors" to target.knowledge.anchors.size, "targetUnresolved" to target.knowledge.unresolved.size,
            "sourceStrategyCounts" to strategyCounts(source.knowledge), "targetStrategyCounts" to strategyCounts(target.knowledge),
            "requiredPublishedRules" to publishedRuleChecks,
            "shapeRounds" to shapes.map { mapOf("runId" to it.runId, "apkSha256" to it.apk.sha256, "anchors" to it.knowledge.anchors.size) },
            "extraVersionReadbacks" to extraReadbacks,
            "sourceReadback" to sourceReadback, "targetReadback" to targetReadback, "upgradedV03" to upgrades,
            "inputHashesUnchanged" to inputArtifacts.values.toList(), "freshMatchingReproduced" to true, "publicationReplayIdentical" to true))
        println("v0.4 real-case acceptance: ${out.resolve("acceptance.json")}")
    }
}
