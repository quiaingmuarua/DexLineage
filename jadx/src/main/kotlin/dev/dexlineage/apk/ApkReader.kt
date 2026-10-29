package dev.dexlineage.apk

import dev.dexlineage.io.ExecutionException
import dev.dexlineage.io.Identities
import dev.dexlineage.io.requireInput
import dev.dexlineage.model.DecompiledClass
import dev.dexlineage.model.ScanResult
import dev.dexlineage.model.ScanStats
import dev.dexlineage.model.StringUseSite
import jadx.api.JadxArgs
import jadx.api.JadxDecompiler
import jadx.api.plugins.JadxPlugin
import jadx.api.plugins.loader.JadxPluginLoader
import jadx.api.plugins.input.insns.Opcode
import jadx.plugins.input.dex.DexInputPlugin
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

/** Reads raw DEX facts separately from the Java presentation used for review. */
object ApkReader {
    private val dexEntryPattern = Regex("classes(?:[0-9]+)?\\.dex")
    private val siteOrder = compareBy<StringUseSite>(
        { it.dexEntry }, { it.classDescriptor }, { it.methodDescriptor },
        { it.codeUnitOffset }, { it.fileOffset }, { it.literal },
    )

    fun scan(apk: Path, literals: Set<String>): ScanResult {
        requireInput(Files.isRegularFile(apk), "Missing APK: $apk")
        val started = System.nanoTime()
        val classes = sortedMapOf<String, String>()
        val uses = literals.sorted().associateWith { mutableListOf<StringUseSite>() }
        val diagnostics = mutableListOf<String>()
        var methods = 0L
        var instructions = 0L
        var strings = 0L
        val input = DexInputPlugin()

        try {
            ZipFile(apk.toFile()).use { zip ->
                val entries = zip.entries().asSequence().filter { !it.isDirectory && dexEntryPattern.matches(it.name) }
                    .sortedBy { it.name }.toList()
                if (entries.isEmpty()) throw ExecutionException("APK contains no root classes*.dex entries: $apk")
                if (entries.map { it.name }.distinct().size != entries.size) {
                    throw ExecutionException("APK contains duplicate DEX entry names: $apk")
                }
                for (entry in entries) {
                    try {
                        val bytes = zip.getInputStream(entry).use { it.readAllBytes() }
                        val expectedClasses = dexClassCount(bytes)
                        var visitedClasses = 0
                        input.loadDex(bytes, entry.name).use { loader ->
                            loader.visitClasses { cls ->
                                visitedClasses++
                                var owner = "<unreadable class>"
                                try {
                                    owner = cls.type
                                    Identities.requireDescriptor(owner)
                                    val previous = classes.putIfAbsent(owner, entry.name)
                                    if (previous != null) {
                                        diagnostics += "Duplicate class $owner in $previous and ${entry.name}"
                                    }
                                    cls.visitFieldsAndMethods({}, { method ->
                                        methods++
                                        var methodName = "<unreadable method>"
                                        try {
                                            val reader = method.codeReader
                                            if (reader != null) {
                                                val ref = method.methodRef
                                                ref.load()
                                                methodName = "${ref.name}(${ref.argTypes.joinToString("")})${ref.returnType}"
                                                reader.visitInstructions { insn ->
                                                    instructions++
                                                    if (insn.opcode == Opcode.CONST_STRING) {
                                                        // The input API normalizes const-string/jumbo to the same opcode.
                                                        insn.decode()
                                                        strings++
                                                        val literal = insn.indexAsString
                                                        uses[literal]?.add(
                                                            StringUseSite(entry.name, owner, methodName, insn.offset, insn.fileOffset, literal),
                                                        )
                                                    }
                                                }
                                            }
                                        } catch (e: Exception) {
                                            diagnostics += "${entry.name}: $owner->$methodName: ${errorText(e)}"
                                        }
                                    })
                                } catch (e: Exception) {
                                    diagnostics += "${entry.name}: $owner: ${errorText(e)}"
                                }
                            }
                        }
                        if (visitedClasses != expectedClasses) {
                            diagnostics += "${entry.name}: enumerated $visitedClasses of $expectedClasses class definitions"
                        }
                    } catch (e: Exception) {
                        diagnostics += "${entry.name}: ${errorText(e)}"
                    }
                }
            }
        } catch (e: ExecutionException) {
            throw e
        } catch (e: Exception) {
            throw ExecutionException("Cannot scan APK $apk: ${errorText(e)}", e)
        }

        return ScanResult(
            classes.toMap(),
            uses.mapValues { (_, value) -> value.sortedWith(siteOrder) },
            ScanStats(classes.size, methods, instructions, strings, elapsedMillis(started), diagnostics.sorted()),
        )
    }

    fun decompile(apk: Path, descriptors: Set<String>, workDir: Path): List<DecompiledClass> {
        requireInput(Files.isRegularFile(apk), "Missing APK: $apk")
        descriptors.forEach(Identities::requireDescriptor)
        if (descriptors.isEmpty()) return emptyList()
        Files.createDirectories(workDir)
        val args = JadxArgs().apply {
            inputFiles = emptyList()
            isSkipResources = true
            isSkipFilesSave = true
            outDir = workDir.toAbsolutePath().toFile()
            threadsCount = 2
            isDeobfuscationOn = false
            isUseSourceNameAsClassAlias = false
            renameFlags = emptySet()
            // Do not discover GUI, scripting, or user-installed plugins and their caches.
            pluginLoader = object : JadxPluginLoader {
                override fun load(): List<JadxPlugin> = listOf(DexInputPlugin())
                override fun close() = Unit
            }
        }
        try {
            JadxDecompiler(args).use { jadx ->
                // An empty inputFiles list bypasses resource-table loading in JADX 1.5.0.
                // skipResources alone does not do so.
                jadx.addCustomCodeLoader(DexInputPlugin().loadFiles(listOf(apk.toAbsolutePath())))
                jadx.load()
                val loadErrors = jadx.errorsCount
                return descriptors.sorted().map { descriptor ->
                    val expectedRaw = Identities.rawName(descriptor)
                    val cls = jadx.searchJavaClassByOrigFullName(expectedRaw)
                        ?: throw ExecutionException("JADX could not resolve original class $descriptor in $apk")
                    if (cls.rawName != expectedRaw) {
                        throw ExecutionException("JADX resolved $descriptor to a different original name: ${cls.rawName}")
                    }
                    val started = System.nanoTime()
                    val beforeErrors = jadx.errorsCount
                    val beforeWarnings = jadx.warnsCount
                    val diagnostics = mutableListOf<String>()
                    if (loadErrors != 0) diagnostics += "JADX load recorded $loadErrors errors"
                    val java = try {
                        cls.code
                    } catch (e: Exception) {
                        diagnostics += "Java decompilation failed: ${errorText(e)}"
                        ""
                    }
                    diagnostics += codeDiagnostics(java, jadx.errorsCount - beforeErrors, jadx.warnsCount - beforeWarnings)
                    val incomplete = diagnostics.isNotEmpty()
                    val smali = if (incomplete) {
                        try { cls.smali } catch (e: Exception) {
                            diagnostics += "Smali retrieval failed: ${errorText(e)}"
                            null
                        }
                    } else null
                    if (java.isBlank() && smali.isNullOrBlank()) {
                        throw ExecutionException("No readable Java or Smali for $descriptor: ${diagnostics.joinToString("; ")}")
                    }
                    DecompiledClass(descriptor, java, smali, incomplete, diagnostics.toList(), elapsedMillis(started))
                }
            }
        } catch (e: ExecutionException) {
            throw e
        } catch (e: Exception) {
            throw ExecutionException("Cannot read class evidence from $apk: ${errorText(e)}", e)
        }
    }

    internal fun codeDiagnostics(code: String, errors: Int, warnings: Int): List<String> = buildList {
        if (code.isBlank()) add("JADX returned empty Java source")
        if ("Method not decompiled:" in code) add("Java source contains Method not decompiled placeholder")
        if ("Code decompiled incorrectly" in code) add("Java source reports incorrectly decompiled code")
        if ("Method dump skipped" in code) add("Java source contains a skipped method dump")
        if ("JADX WARN:" in code) add("Java source includes JADX warnings")
        if ("JADX ERROR:" in code) add("Java source includes JADX errors")
        if (errors > 0) add("JADX recorded $errors new errors while reading this class")
        if (warnings > 0) add("JADX recorded $warnings new warnings while reading this class")
    }

    private fun dexClassCount(bytes: ByteArray): Int {
        check(bytes.size >= 112) { "Truncated DEX header" }
        check(bytes[0] == 'd'.code.toByte() && bytes[1] == 'e'.code.toByte() && bytes[2] == 'x'.code.toByte() && bytes[3] == '\n'.code.toByte()) { "Invalid DEX magic" }
        val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        check(header.getInt(40) == 0x12345678) { "Unsupported DEX endianness" }
        check(header.getInt(32) == bytes.size) { "DEX file size differs from header" }
        return header.getInt(96).also { check(it >= 0) { "Invalid DEX class definition count" } }
    }

    private fun errorText(error: Exception): String = "${error.javaClass.simpleName}: ${error.message.orEmpty()}"
    private fun elapsedMillis(started: Long): Long = (System.nanoTime() - started) / 1_000_000
}
