package dev.dexlineage.cli

import com.google.gson.JsonParser
import dev.dexlineage.analysis.*
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import dev.dexlineage.rules.ResolutionEngine
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import java.util.UUID
import kotlin.test.*

/** Explicit local acceptance; private RPC names and expected outcomes come only from its manifest. */
object GrpcTopicAcceptance {
    private data class Round(val run: String = "", val output: String = "")
    private data class RequiredPair(val service: String = "", val rpc: String = "")
    private data class Manifest(val schemaVersion: Int = SCHEMA_VERSION,
        val baseKnowledge: String = "", val referenceKnowledge: List<String> = emptyList(),
        val rounds: List<Round> = emptyList(), val discovery: String = "",
        val reviewServices: List<String> = emptyList(), val requiredPairs: List<RequiredPair> = emptyList(),
        val preservedInputs: List<Artifact> = emptyList())

    fun run(config: Path) {
        val properties = Properties().apply { Files.newBufferedReader(config).use(::load) }
        fun configured(key: String) = config.toAbsolutePath().parent.resolve(
            requireNotNull(properties.getProperty(key)) { "Missing $key" }).normalize()
        val manifestFile = configured("caseManifest")
        val manifest = JsonFiles.read(manifestFile, Manifest::class.java)
        fun resolve(value: String): Path {
            require(value.isNotBlank()) { "Empty acceptance path" }
            return manifestFile.parent.resolve(value).normalize()
        }
        require(manifest.rounds.isNotEmpty() && manifest.reviewServices.isNotEmpty() && manifest.requiredPairs.isNotEmpty()) {
            "The case requires producer rounds, review services and independent RPC acceptance pairs"
        }
        val out = configured("acceptanceRoot").resolve(UUID.randomUUID().toString())
        Files.createDirectories(out)
        val inputs = linkedMapOf<String, Artifact>()
        fun remember(artifact: Artifact) {
            assertTrue(inputs.putIfAbsent(artifact.path, artifact)?.let { it == artifact } != false,
                "One input path has conflicting hashes")
            Digests.verify(artifact)
        }
        remember(Digests.artifact(config)); remember(Digests.artifact(manifestFile))
        manifest.preservedInputs.forEach(::remember)
        val originalBase = KnowledgeFiles.read(resolve(manifest.baseKnowledge))
        remember(Digests.artifact(resolve(manifest.baseKnowledge)))
        val references = manifest.referenceKnowledge.map { file ->
            val path = resolve(file)
            remember(Digests.artifact(path))
            KnowledgeFiles.read(path).also { assertEquals(originalBase.artifact.sha256, it.artifact.sha256) }
        }
        val checkedAnchors = mutableSetOf<String>()
        val matching = mutableListOf<Map<String, Any>>()
        val publications = mutableListOf<Map<String, Any>>()
        fun anchorId(a: SupportAnchor) = "${a.binding.owner.apkSha256}:${a.key}:${a.resolution.resolutionId}"
        fun available(run: AnalysisRun): Map<String, SupportAnchor> {
            val definitions = run.anchorTasks.associate { it.key to it.rule }
            val anchors = run.baseKnowledge?.anchors.orEmpty().filter {
                it.rule == definitions[it.key] && it.resolution.engineBuildId == run.engineBuildId
            }.associateBy { it.key }.toMutableMap()
            while (true) {
                val stale = anchors.filter { (_, a) ->
                    a.rule.requires.values.any { it !in anchors } ||
                        a.resolution.dependencies != a.rule.requires.mapValues { (_, key) -> anchors.getValue(key) }
                }.keys
                if (stale.isEmpty()) break
                stale.forEach(anchors::remove)
            }
            anchors.values.forEach {
                assertEquals(run.apk.sha256, it.binding.owner.apkSha256)
                assertTrue(anchorId(it) in checkedAnchors, "Manifest omitted an earlier fresh anchor producer: ${it.key}")
            }
            return anchors
        }
        val rounds = manifest.rounds.mapIndexed { index, location ->
            val label = "round-${index + 1}"
            val runDir = resolve(location.run)
            val output = resolve(location.output)
            val run = AnalysisService.readRun(runDir)
            val knowledge = KnowledgeFiles.read(output.resolve("knowledge.json"))
            assertEquals(ResolutionEngine.buildId(), run.engineBuildId, "Case must use the frozen current implementation")
            assertEquals(originalBase.artifact.sha256, run.apk.sha256)
            remember(run.apk); remember(run.rulesFile)
            listOfNotNull(run.baseFile, run.discoveryFile, run.corpusFile).forEach(::remember)
            val anchors = available(run)
            val rules = run.tasks.map { it.rule } + run.anchorTasks.map { it.rule }
            val saved = (run.tasks.mapNotNull { it.resolution } + run.anchorTasks.mapNotNull { it.resolution })
                .groupBy { it.rule.revisionId }
            assertTrue(saved.values.all { it.distinct().size == 1 })
            val waiting = (run.tasks.filter { it.resolution == null }.map { it.rule.revisionId to it.waitingFor } +
                run.anchorTasks.filter { it.resolution == null }.map { it.rule.revisionId to it.waitingFor }).toMap()
            val fresh = ResolutionEngine.execute(run.apk, rules, out.resolve("$label-matching"), anchors)
            assertEquals(run.classInventory, fresh.scan.classes)
            assertTrue(fresh.scan.stats.diagnostics.isEmpty())
            assertEquals(saved.mapValues { it.value.first() }, fresh.resolutions)
            assertEquals(waiting, fresh.waiting)
            run.anchorTasks.filter { it.resolution?.status == ResolutionStatus.UNIQUE }.forEach {
                checkedAnchors += "${run.apk.sha256}:${it.key}:${it.resolution!!.resolutionId}"
            }
            val replay = out.resolve("$label-publication")
            AnalysisService.publish(runDir, replay, output.resolve("report.json"))
            for (file in listOf("knowledge.json", "mapping.tiny")) {
                assertEquals(Files.readString(output.resolve(file)), Files.readString(replay.resolve(file)), "Replay differs: $label/$file")
            }
            MappingOutput.verifyContents(output.resolve("mapping.tiny"), knowledge.entries.map {
                AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name))
            })
            matching += mapOf("round" to label, "executed" to fresh.resolutions.size,
                "waiting" to fresh.waiting.size, "scanMillis" to fresh.scan.stats.elapsedMillis)
            publications += mapOf("round" to label, "knowledgeId" to knowledge.knowledgeId,
                "confirmed" to knowledge.entries.size, "anchors" to knowledge.anchors.size, "identical" to true)
            Triple(runDir, run, knowledge)
        }
        val (finalDir, finalRun, finalKnowledge) = rounds.last()
        val selected = finalRun.tasks.filter { task -> task.rule.parameters.getAsJsonArray("selectors")?.any { selector ->
            selector.asJsonObject["service"].asString in manifest.reviewServices
        } == true }
        assertTrue(selected.isNotEmpty(), "No tasks for configured services")
        val taskViews = AnalysisService.tasks(finalDir, "ALL", 0, Int.MAX_VALUE).items.associateBy { it.task.taskId }
        assertTrue(selected.none { taskViews.getValue(it.taskId).state == TaskState.UNREVIEWED },
            "Every selected class needs a real semantic decision or an invalid mechanical result")
        originalBase.entries.forEach { old ->
            val current = finalKnowledge.entries.single { it.binding == old.binding }
            assertEquals(old.semanticId, current.semanticId)
            assertEquals(old.name, current.name)
        }
        val referenceByBinding = references.flatMap { it.entries }.associateBy { it.binding }
        val reused = finalKnowledge.entries.mapNotNull { current -> referenceByBinding[current.binding]?.let { old ->
            assertEquals(old.semanticId, current.semanticId)
            assertEquals(old.name, current.name)
            current.semanticId
        } }
        assertTrue(reused.isNotEmpty(), "The real case must exercise reference identity reuse")
        assertEquals(finalKnowledge.entries.size, finalKnowledge.entries.map { it.binding }.distinct().size)
        val oldBindings = (originalBase.entries + references.flatMap { it.entries }).map { it.binding }.toSet()
        val pairResults = manifest.requiredPairs.map { pair ->
            val roles = listOf("request", "response").associateWith { role ->
                val candidates = selected.filter { task -> task.rule.parameters.getAsJsonArray("selectors").any { selector ->
                    val s = selector.asJsonObject
                    s["service"].asString == pair.service && s["rpc"].asString == pair.rpc && s["role"].asString == role
                } }.filter { taskViews.getValue(it.taskId).state == TaskState.ACCEPTED }
                assertEquals(1, candidates.size, "Required RPC role did not obtain one confirmed type: ${pair.service}/${pair.rpc}/$role")
                val task = candidates.single()
                val entry = finalKnowledge.entries.single { it.semanticId == task.semanticId }
                assertEquals(task.resolution?.uniqueRef, entry.binding)
                assertTrue(entry.binding !in oldBindings, "Required new benefit was already in an input package")
                entry.binding
            }
            mapOf("service" to pair.service, "rpc" to pair.rpc, "roles" to roles)
        }
        val discoveryFile = resolve(manifest.discovery)
        val discovery = JsonFiles.read(discoveryFile, AnalysisDiscovery::class.java)
        assertEquals(discovery.discoveryId, discovery.fingerprint())
        remember(Digests.artifact(discoveryFile)); remember(discovery.profileSource)
        val freshDiscoveryResult = AnalysisService.discover(Path.of(discovery.apk.path), Path.of(discovery.profileSource.path),
            out.resolve("fresh-discovery"), discovery.baseFile?.let { Path.of(it.path) })
        val freshDiscovery = JsonFiles.read(Path.of(freshDiscoveryResult.discoveryPath), AnalysisDiscovery::class.java)
        assertEquals(discovery.matches, freshDiscovery.matches)
        assertEquals(discovery.leads, freshDiscovery.leads)
        assertEquals(discovery.classInventory, freshDiscovery.classInventory)
        // Catalog is a projection; compare everything but the document's execution identity if present.
        val oldCatalog = JsonParser.parseString(Files.readString(discoveryFile.parent.resolve("rpc-catalog.json"))).asJsonObject
        val newCatalog = JsonParser.parseString(Files.readString(Path.of(freshDiscoveryResult.discoveryPath).parent.resolve("rpc-catalog.json"))).asJsonObject
        listOf("discoveryId", "createdAt", "elapsedMillis").forEach { oldCatalog.remove(it); newCatalog.remove(it) }
        assertEquals(oldCatalog, newCatalog)
        val finalOutput = resolve(manifest.rounds.last().output)
        val readback = MappingOutput.verify(Path.of(finalRun.apk.path), finalOutput.resolve("mapping.tiny"),
            finalKnowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) },
            out.resolve("independent-readback"))
        inputs.values.forEach(Digests::verify)
        JsonFiles.writeNew(out.resolve("acceptance.json"), mapOf("schemaVersion" to SCHEMA_VERSION,
            "kind" to "grpc-analysis-acceptance", "knowledgeId" to finalKnowledge.knowledgeId,
            "matching" to matching, "publicationReplay" to publications, "freshDiscoveryReproduced" to true,
            "reviewServices" to manifest.reviewServices, "selectedClassTasks" to selected.size,
            "selectedStates" to selected.groupingBy { taskViews.getValue(it.taskId).state }.eachCount(),
            "referenceIdentitiesReused" to reused, "requiredPairs" to pairResults,
            "confirmed" to finalKnowledge.entries.size, "readback" to readback,
            "preservedInputs" to inputs.size))
    }
}
