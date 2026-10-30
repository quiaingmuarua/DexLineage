package dev.dexlineage.cli

import dev.dexlineage.analysis.AnalysisService
import dev.dexlineage.migration.MigrationService
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import java.nio.file.Path
import kotlin.system.exitProcess

private const val HELP = """DexLineage 0.4.0
  analysis import-jadx --apk <apk> --project <project.jadx> --out <new-directory>
  analysis targets   --corpus <corpus.json> [--run <directory>] [--state ...] [--offset N] [--limit N]
  analysis discover  --apk <apk> --profile <profile.json> --out <new-directory> [--base-knowledge <knowledge.json>]
  analysis prepare   --apk <apk> --rules <rules.json> --run <new-directory> [--corpus <corpus.json>] [--base-knowledge <knowledge.json>]
  analysis tasks     --run <directory> [--state UNREVIEWED|ACCEPTED|REJECTED|DEFERRED|INVALID|ALL] [--offset N] [--limit N]
  analysis inspect   --run <directory> --task <task-id,...>
  analysis submit    --run <directory> --review <review-batch.json>
  analysis publish   --run <directory> --out <new-directory> [--at <previous-report.json>]
  migration prepare  --knowledge <knowledge.json> --source-apk <apk> --target-apk <apk> --run <new-directory> [--min-confidence HIGH] [--rules <overrides.json>] [--target-base <knowledge.json>]
  migration tasks    --run <directory> [--state ...] [--offset N] [--limit N]
  migration inspect  --run <directory> --task <task-id,...> [--candidate <task-id=Lclass;,...> ...]
  migration submit   --run <directory> --review <review-batch.json>
  migration publish  --run <directory> --out <new-directory> [--at <previous-report.json>]
  knowledge verify   --knowledge <knowledge.json> --apk <apk> --work <directory>
  knowledge import-s1 --output <S1-output-directory> --run <S1-run-directory> --out <new-directory>
  knowledge import-v02 --knowledge <v02-knowledge.json> --apk <apk> --out <new-directory>
  knowledge import-v03 --knowledge <v03-knowledge.json> --apk <apk> --out <new-directory> [--history <manifest.json>]
Exit codes: 0 completed (deferred allowed), 2 invalid inputs/review, 1 execution failure.
"""

fun main(args: Array<String>) { exitProcess(runCli(args)) }

fun runCli(args: Array<String>): Int = try {
    when (args.firstOrNull()) {
        null, "--help", "help", "-h" -> { println(HELP); 0 }
        "--version" -> { println(JsonFiles.encode(mapOf("schemaVersion" to SCHEMA_VERSION, "version" to TOOL_VERSION, "jadxVersion" to JADX_VERSION))); 0 }
        "prepare", "inspect", "finalize", "bootstrap" -> throw ValidationException("Old commands were replaced. Use analysis discover/prepare or migration prepare; upgrade old knowledge explicitly with knowledge import-v02/import-s1. Run --help.")
        else -> {
            requireInput(args.size >= 2, "Specify a scenario and operation; run --help")
            val scene = args[0]; val operation = args[1]
            val allowed = when ("$scene $operation") {
                "analysis import-jadx" -> setOf("--apk", "--project", "--out")
                "analysis targets" -> setOf("--corpus", "--run", "--state", "--offset", "--limit")
                "analysis discover" -> setOf("--apk", "--profile", "--out", "--base-knowledge")
                "analysis prepare" -> setOf("--apk", "--rules", "--run", "--base-knowledge", "--corpus")
                "analysis tasks", "migration tasks" -> setOf("--run", "--state", "--offset", "--limit")
                "analysis inspect" -> setOf("--run", "--task")
                "migration inspect" -> setOf("--run", "--task", "--candidate")
                "analysis submit", "migration submit" -> setOf("--run", "--review")
                "analysis publish", "migration publish" -> setOf("--run", "--out", "--at")
                "migration prepare" -> setOf("--knowledge", "--source-apk", "--target-apk", "--run", "--min-confidence", "--rules", "--target-base")
                "knowledge verify" -> setOf("--knowledge", "--apk", "--work")
                "knowledge import-s1" -> setOf("--output", "--run", "--out")
                "knowledge import-v02" -> setOf("--knowledge", "--apk", "--out")
                "knowledge import-v03" -> setOf("--knowledge", "--apk", "--out", "--history")
                else -> throw ValidationException("Unknown scene operation: $scene $operation")
            }
            requireInput((args.size - 2) % 2 == 0, "Options require values")
            val options = linkedMapOf<String, MutableList<String>>()
            for (i in 2 until args.size step 2) {
                requireInput(args[i] in allowed, "Unknown option: ${args[i]}")
                requireInput(args[i] == "--candidate" || args[i] !in options, "Duplicate option: ${args[i]}")
                requireInput(args[i + 1].isNotBlank(), "Empty option: ${args[i]}")
                options.getOrPut(args[i]) { mutableListOf() } += args[i + 1]
            }
            fun value(key: String) = options[key]?.single() ?: throw ValidationException("Missing option: $key")
            fun path(key: String) = Path.of(value(key))
            fun number(key: String, default: Int): Int = options[key]?.single()?.toIntOrNull()?.also { requireInput(it >= 0, "Negative $key") }
                ?: if (key in options) throw ValidationException("Invalid integer $key") else default
            fun selected(): Map<String, Set<String>> {
                val selections = linkedMapOf<String, Set<String>>()
                options["--candidate"].orEmpty().forEach { option ->
                    val pair = option.split('=', limit = 2)
                    requireInput(pair.size == 2 && pair.all { it.isNotBlank() }, "Expected --candidate task=Lclass;,...")
                    requireInput(pair[0] !in selections, "Duplicate candidate selection for task ${pair[0]}")
                    selections[pair[0]] = pair[1].split(',').onEach(Identities::requireDescriptor).toSet()
                }
                return selections
            }
            val result: Any = when ("$scene $operation") {
                "analysis import-jadx" -> AnalysisService.importJadx(path("--apk"), path("--project"), path("--out"))
                "analysis targets" -> AnalysisService.targets(path("--corpus"), options["--run"]?.single()?.let(Path::of), options["--state"]?.single(), number("--offset", 0), number("--limit", 20))
                "analysis discover" -> AnalysisService.discover(path("--apk"), path("--profile"), path("--out"), options["--base-knowledge"]?.single()?.let(Path::of))
                "analysis prepare" -> AnalysisService.prepare(path("--apk"), path("--rules"), path("--run"), options["--base-knowledge"]?.single()?.let(Path::of), options["--corpus"]?.single()?.let(Path::of)).let {
                    mapOf("runId" to it.runId, "run" to path("--run").toAbsolutePath().toString(), "tasks" to it.tasks.size,
                        "resolutions" to it.tasks.mapNotNull { task -> task.resolution?.status }.groupingBy { status -> status }.eachCount(),
                        "waiting" to it.tasks.count { task -> task.waitingFor.isNotEmpty() },
                        "inherited" to it.tasks.count { task -> task.executionState == dev.dexlineage.analysis.AnalysisExecutionState.INHERITED }, "anchors" to it.anchorTasks.size)
                }
                "analysis tasks" -> AnalysisService.tasks(path("--run"), options["--state"]?.single(), number("--offset", 0), number("--limit", 20))
                "analysis inspect" -> AnalysisService.inspect(path("--run"), value("--task").split(',').toSet())
                "analysis submit" -> AnalysisService.submit(path("--run"), path("--review"))
                "analysis publish" -> AnalysisService.publish(path("--run"), path("--out"), options["--at"]?.single()?.let(Path::of))
                "migration prepare" -> {
                    val level = checkedInput("min-confidence") { Confidence.valueOf(options["--min-confidence"]?.single()?.uppercase() ?: "HIGH") }
                    MigrationService.prepare(path("--knowledge"), path("--source-apk"), path("--target-apk"), path("--run"), level, options["--rules"]?.single()?.let(Path::of), options["--target-base"]?.single()?.let(Path::of)).let {
                        mapOf("runId" to it.runId, "run" to path("--run").toAbsolutePath().toString(), "tasks" to it.tasks.size,
                            "resolutions" to it.tasks.mapNotNull { task -> task.resolution?.status }.groupingBy { status -> status }.eachCount(),
                            "waiting" to it.tasks.count { task -> task.waitingFor.isNotEmpty() },
                            "inherited" to it.tasks.count { task -> task.executionState == dev.dexlineage.migration.MigrationExecutionState.INHERITED }, "anchors" to it.anchorTasks.size,
                            "sourceScan" to it.sourceScan, "targetScan" to it.targetScan,
                            "analysisMillis" to it.analysisMillis, "diagnostics" to it.analysisDiagnostics)
                    }
                }
                "migration tasks" -> MigrationService.tasks(path("--run"), options["--state"]?.single(), number("--offset", 0), number("--limit", 20))
                "migration inspect" -> MigrationService.inspect(path("--run"), value("--task").split(',').toSet(), selected())
                "migration submit" -> MigrationService.submit(path("--run"), path("--review"))
                "migration publish" -> MigrationService.publish(path("--run"), path("--out"), options["--at"]?.single()?.let(Path::of))
                "knowledge verify" -> {
                    val knowledge = KnowledgeFiles.read(path("--knowledge"))
                    requireInput(Digests.file(path("--apk")) == knowledge.artifact.sha256, "Knowledge APK SHA-256 mismatch")
                    val renames = knowledge.entries.map { AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name)) }
                    MappingOutput.verify(path("--apk"), path("--knowledge").toAbsolutePath().parent.resolve("mapping.tiny"), renames, path("--work"))
                }
                "knowledge import-v02" -> dev.dexlineage.migration.V02Importer.importKnowledge(path("--knowledge"), path("--apk"), path("--out")).let {
                    mapOf("knowledgeId" to it.knowledgeId, "confirmed" to it.entries.size, "unresolved" to it.unresolved.size, "output" to path("--out").toAbsolutePath().toString())
                }
                "knowledge import-v03" -> dev.dexlineage.migration.V03Importer.importKnowledge(path("--knowledge"), path("--apk"), path("--out"),
                    options["--history"]?.single()?.let { file ->
                        checkedInput("v0.3 history manifest") {
                            val manifest = Path.of(file).toAbsolutePath()
                            val json = com.google.gson.JsonParser.parseString(java.nio.file.Files.readString(manifest)).asJsonObject
                            requireInput(json.keySet() == setOf("schemaVersion", "knowledgeFiles") && json["schemaVersion"].asInt == SCHEMA_VERSION, "Invalid history manifest")
                            json.getAsJsonArray("knowledgeFiles").map { manifest.parent.resolve(it.asString).normalize() }
                        }
                    }.orEmpty()).let {
                    mapOf("knowledgeId" to it.knowledgeId, "confirmed" to it.entries.size, "unresolved" to it.unresolved.size, "output" to path("--out").toAbsolutePath().toString())
                }
                else -> dev.dexlineage.migration.S1Importer.importKnowledge(path("--output"), path("--run"), path("--out")).let {
                    mapOf("knowledgeId" to it.knowledgeId, "confirmed" to it.entries.size, "unresolved" to it.unresolved.size, "output" to path("--out").toAbsolutePath().toString())
                }
            }
            println(JsonFiles.encode(mapOf("schemaVersion" to SCHEMA_VERSION, "scenario" to scene, "operation" to operation, "result" to result)))
            0
        }
    }
} catch (e: ValidationException) {
    System.err.println(JsonFiles.encode(mapOf("schemaVersion" to SCHEMA_VERSION, "error" to "validation", "message" to e.message))); 2
} catch (e: Exception) {
    System.err.println(JsonFiles.encode(mapOf("schemaVersion" to SCHEMA_VERSION, "error" to "execution", "message" to (e.message ?: e.javaClass.name)))); 1
}
