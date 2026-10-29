package dev.dexlineage.io

import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import dev.dexlineage.model.*
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

class ValidationException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
class ExecutionException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
fun requireInput(condition: Boolean, message: String) { if (!condition) throw ValidationException(message) }
fun <T> checkedInput(description: String, block: () -> T): T = try { block() }
catch (e: ValidationException) { throw e }
catch (e: ExecutionException) { throw e }
catch (e: Exception) { throw ValidationException("Invalid $description: ${e.message}", e) }

object JsonFiles {
    val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
    fun encode(value: Any): String = gson.toJson(value) + "\n"
    fun writeNew(path: Path, value: Any) { Files.writeString(path, encode(value), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW) }
    fun <T> read(path: Path, type: Class<T>, schemaVersion: Int = SCHEMA_VERSION): T = try {
        requireInput(Files.isRegularFile(path), "Missing JSON file: $path")
        val json = JsonParser.parseString(Files.readString(path)).asJsonObject
        val version = json.get("schemaVersion")
        requireInput(version != null && version.isJsonPrimitive && version.asJsonPrimitive.isNumber && version.asString == schemaVersion.toString(), "Expected schemaVersion $schemaVersion: $path")
        gson.fromJson(json, type) ?: throw ValidationException("Empty JSON: $path")
    } catch (e: ValidationException) { throw e } catch (e: Exception) { throw ValidationException("Invalid ${type.simpleName} in $path: ${e.message}", e) }
}

object Digests {
    fun bytes(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun text(text: String): String = bytes(text.toByteArray(StandardCharsets.UTF_8))
    fun file(path: Path): String {
        val md = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input ->
            val buf = ByteArray(128 * 1024)
            while (true) { val n = input.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
    fun artifact(path: Path): Artifact {
        requireInput(Files.isRegularFile(path), "Missing input file: $path")
        return Artifact(path.toAbsolutePath().normalize().toString(), file(path))
    }
    fun verify(artifact: Artifact) { requireInput(file(Path.of(artifact.path)) == artifact.sha256, "Input SHA-256 changed: ${artifact.path}") }
}

object Identities {
    fun requireDescriptor(value: String) { requireInput(value.startsWith("L") && value.endsWith(";") && value.length > 2 && value.substring(1, value.length - 1).none { it in ".;[\\" || it.isWhitespace() }, "Invalid class descriptor: $value") }
    fun rawName(descriptor: String): String { requireDescriptor(descriptor); return descriptor.substring(1, descriptor.length - 1).replace('/', '.') }
    fun descriptor(rawName: String): String = "L${rawName.replace('.', '/')};".also(::requireDescriptor)
    fun renamedFullName(descriptor: String, simpleName: String): String {
        requireInput(simpleName.isNotEmpty() && Character.isJavaIdentifierStart(simpleName[0]) && simpleName.all(Character::isJavaIdentifierPart) && !javax.lang.model.SourceVersion.isKeyword(simpleName), "Expected simple Java class alias: $simpleName")
        val raw = rawName(descriptor)
        return raw.substringBeforeLast('.', "").let { if (it.isEmpty()) simpleName else "$it.$simpleName" }
    }
    fun evidenceId(runId: String, ref: ClassRef): String = Digests.text("$runId\n${ref.apkSha256}\n${ref.dexEntry}\n${ref.descriptor}")
}

fun createNewDirectory(path: Path) {
    requireInput(!Files.exists(path), "Output directory already exists: $path")
    path.toAbsolutePath().parent?.let { Files.createDirectories(it) }
    Files.createDirectory(path)
}
