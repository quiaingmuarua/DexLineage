package dev.dexlineage.cli.fixtures

import jadx.api.plugins.input.data.attributes.types.SourceFileAttr
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode
import jadx.plugins.input.dex.DexInputPlugin
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.ZipInputStream

data class RawDexField(val name: String, val type: String, val flags: Int)
data class RawDexFieldRef(val owner: String, val name: String, val type: String)
data class RawDexMethodRef(val owner: String, val name: String, val args: List<String>, val result: String) {
    val descriptor: String get() = "(${args.joinToString("")})$result"
}
data class RawDexInstruction(val opcode: Opcode, val offset: Int, val regs: List<Int>,
    val literal: String?, val method: RawDexMethodRef?, val fieldOwner: String?, val fieldName: String?, val fieldType: String?,
    val typeReference: String? = null)
data class RawDexMethod(val ref: RawDexMethodRef, val flags: Int, val instructions: List<RawDexInstruction>)
data class RawDexClass(val descriptor: String, val dexEntry: String, val sourceFiles: List<String>,
    val fields: List<RawDexField>, val methods: List<RawDexMethod>, val accessFlags: Int = 0,
    val superType: String? = null, val interfaces: List<String> = emptyList())
data class RawDexIndex(val apkSha256: String, val classes: Map<String, RawDexClass>)

/** Test-side raw input only: no production matcher, saved Resolution, Java rendering or rename map. */
object RawDex {
    private val cache = ConcurrentHashMap<String, RawDexIndex>()

    fun read(apk: Path): RawDexIndex {
        require(Files.isRegularFile(apk)) { "Fixture APK does not exist: $apk" }
        // Hash and parse the same bytes. A changed file can never reuse a path-based cached index.
        val bytes = Files.readAllBytes(apk)
        val sha256 = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        return cache.computeIfAbsent(sha256) { parse(bytes, sha256) }
    }

    private fun parse(bytes: ByteArray, sha256: String): RawDexIndex {
        val dexFiles = linkedMapOf<String, ByteArray>()
        var manifest = false
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.name == "AndroidManifest.xml") manifest = true
                check(listOf(".java", ".kt", "mapping.txt", "cases.json").none(entry.name::endsWith)) {
                    "APK contains oracle or original source materials: ${entry.name}"
                }
                if (Regex("classes(?:[0-9]+)?\\.dex").matches(entry.name)) {
                    check(dexFiles.put(entry.name, zip.readAllBytes()) == null) { "Duplicate DEX entry ${entry.name}" }
                }
                zip.closeEntry()
            }
        }
        check(manifest) { "Not an APK: missing AndroidManifest.xml" }
        check(dexFiles.isNotEmpty()) { "Fixture APK contains no DEX" }
        val classes = linkedMapOf<String, RawDexClass>()
        for ((dexEntry, dexBytes) in dexFiles) {
            DexInputPlugin().loadDex(dexBytes, dexEntry).use { loader ->
                loader.visitClasses { cls ->
                    val fields = mutableListOf<RawDexField>()
                    val methods = mutableListOf<RawDexMethod>()
                    cls.visitFieldsAndMethods({ fields += RawDexField(it.name, it.type, it.accessFlags) }, { method ->
                        val ref = method.methodRef.also { it.load() }
                        val instructions = mutableListOf<RawDexInstruction>()
                        method.codeReader?.visitInstructions { insn ->
                            insn.decode()
                            val call = if (insn.indexType == InsnIndexType.METHOD_REF) insn.indexAsMethod.also { it.load() } else null
                            val field = if (insn.indexType == InsnIndexType.FIELD_REF) insn.indexAsField else null
                            instructions += RawDexInstruction(insn.opcode, insn.offset, (0 until insn.regsCount).map { insn.getReg(it) },
                                if (insn.opcode == Opcode.CONST_STRING) insn.indexAsString else null,
                                call?.let { RawDexMethodRef(it.parentClassType, it.name, it.argTypes.toList(), it.returnType) },
                                field?.parentClassType, field?.name, field?.type,
                                if (insn.indexType == InsnIndexType.TYPE_REF) insn.indexAsType else null)
                        }
                        methods += RawDexMethod(RawDexMethodRef(ref.parentClassType, ref.name, ref.argTypes.toList(), ref.returnType),
                            method.accessFlags, instructions.toList())
                    })
                    val clazz = RawDexClass(cls.type, dexEntry, cls.attributes.filterIsInstance<SourceFileAttr>().map { it.fileName },
                        fields.toList(), methods.toList(), cls.accessFlags, cls.superType, cls.interfacesTypes.toList())
                    check(classes.put(cls.type, clazz) == null) { "Duplicate fixture class ${cls.type}" }
                }
            }
        }
        return RawDexIndex(sha256, classes.toMap())
    }
}
