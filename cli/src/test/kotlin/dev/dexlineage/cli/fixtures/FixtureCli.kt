package dev.dexlineage.cli.fixtures

import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Each invocation is a fresh JVM using exactly the installed application's runtime libraries. */
internal class FixtureCli(private val distribution: Path, val output: Path, private val repository: Path) {
    private var sequence = 0
    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

    init {
        require(Files.isDirectory(distribution.resolve("lib"))) { "Build installDist before fixture integration: $distribution" }
        Files.createDirectories(output)
    }

    fun write(name: String, value: Any): Path = output.resolve(name).also {
        Files.createDirectories(it.parent)
        Files.writeString(it, gson.toJson(value))
    }

    inline fun <reified T> read(path: Path): T = Files.newBufferedReader(path).use { gson.fromJson(it, T::class.java) }

    fun execute(label: String, vararg arguments: Any, expectedExit: Int = 0): JsonElement {
        val args = arguments.map(Any::toString)
        val javaName = if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java"
        val command = listOf(Path.of(System.getProperty("java.home"), "bin", javaName).toString(), "-Xmx1g",
            "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn", "-cp", distribution.resolve("lib").toString() + java.io.File.separator + "*",
            "dev.dexlineage.cli.MainKt") + args
        val directory = output.resolve("commands/${(++sequence).toString().padStart(3, '0')}-$label")
        Files.createDirectories(directory)
        val stdout = directory.resolve("stdout.json")
        val stderr = directory.resolve("stderr.log")
        val record = linkedMapOf<String, Any?>("schemaVersion" to 1, "startedAt" to Instant.now().toString(),
            "arguments" to args, "command" to command, "workingDirectory" to repository.toString(),
            "stdout" to stdout.toString(), "stderr" to stderr.toString(), "timeoutSeconds" to 90,
            "artifactPaths" to args.windowed(2).filter { it[0] in setOf("--run", "--out", "--work", "--review", "--rules", "--knowledge", "--profile") }
                .map { mapOf("option" to it[0], "path" to it[1]) })
        Files.writeString(directory.resolve("command.json"), gson.toJson(record))
        val started = System.nanoTime()
        val process = ProcessBuilder(command).directory(repository.toFile())
            .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start()
        val completed = process.waitFor(90, TimeUnit.SECONDS)
        if (!completed) {
            process.descendants().forEach { it.destroyForcibly() }
            process.destroyForcibly()
            process.waitFor(10, TimeUnit.SECONDS)
        }
        record["elapsedMillis"] = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        record["timedOut"] = !completed
        record["exitCode"] = if (completed) process.exitValue() else null
        Files.writeString(directory.resolve("command.json"), gson.toJson(record))
        assertTrue(completed, "CLI timeout: $directory")
        assertEquals(expectedExit, process.exitValue(), "CLI $label failed; diagnostics $directory\n${Files.readString(stderr)}")
        return if (expectedExit == 0) JsonParser.parseString(Files.readString(stdout)).asJsonObject.get("result")
            ?: JsonParser.parseString(Files.readString(stdout))
        else {
            // SLF4J may precede the structured error, so retain the full stream and check its envelope.
            assertTrue(Files.readString(stderr).contains("\"validation\""), "Expected structured validation error: $directory")
            com.google.gson.JsonNull.INSTANCE
        }
    }

    inline fun <reified T> result(label: String, vararg args: Any): T = gson.fromJson(execute(label, *args), T::class.java)
    val commandCount: Int get() = sequence
}
