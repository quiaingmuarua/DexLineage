package dev.dexlineage.rules.facts

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import jadx.api.plugins.input.data.IClassData
import jadx.api.plugins.input.data.ICodeReader
import jadx.api.plugins.input.ICodeLoader
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode
import jadx.plugins.input.dex.DexInputPlugin
import java.nio.file.Path
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/** One immutable raw-DEX inventory per execution. No display names or desired entities are inputs. */
internal class DexFactSession(val artifact: Artifact, anchors: Set<String>, wantedCalls: Set<MethodRef> = emptySet()) : AutoCloseable {
    data class Field(val owner: String, val name: String, val type: String, val flags: Int = 0) {
        val key get() = "$owner->$name:$type"
    }
    data class MethodId(val owner: String, val name: String, val args: List<String>, val result: String) {
        val descriptor get() = "(${args.joinToString("")})$result"
        val shortId get() = name + descriptor
        val key get() = "$owner->$shortId"
    }
    data class Method(val id: MethodId, val flags: Int, val code: ICodeReader?)
    data class Class(val ref: ClassRef, val parent: String?, val interfaces: List<String>, val flags: Int, val data: IClassData)
    val classes = sortedMapOf<String, Class>()
    private val loaders = mutableListOf<ICodeLoader>()
    private val members = mutableMapOf<String, Pair<List<Field>, List<Method>>>()
    private val traces = mutableMapOf<String, RawTrace>()
    private val implementations = mutableMapOf<String, List<Class>>()
    val callOwners = mutableMapOf<String, MutableSet<String>>()
    data class DirectCall(val source: MethodId, val target: MethodId, val offset: Int)
    val wantedCallSites = mutableListOf<DirectCall>()
    private val recipeCache = mutableMapOf<String, Any>()
    @Suppress("UNCHECKED_CAST")
    fun <T : Any> cachedRecipe(key: String, create: () -> T): T = recipeCache.getOrPut(key, create) as T
    val scan: ScanResult

    init {
        Digests.verify(artifact)
        val began = System.nanoTime()
        val uses = anchors.sorted().associateWith { mutableListOf<StringUseSite>() }
        val callKeys = wantedCalls.map { "${it.owner.descriptor}->${it.name}${it.descriptor}" }.toSet()
        var methodCount = 0L; var instructionCount = 0L; var stringCount = 0L
        try {
            ZipFile(artifact.path).use { zip ->
                val entries = zip.entries().asSequence().filter { it.name.matches(Regex("classes(?:[0-9]+)?\\.dex")) }.sortedBy { it.name }.toList()
                if (entries.isEmpty()) throw ExecutionException("APK contains no DEX")
                if (entries.map { it.name }.distinct().size != entries.size) throw ExecutionException("Duplicate APK DEX entry names")
                entries.forEach { entry ->
                    val bytes = zip.getInputStream(entry).use { it.readAllBytes() }
                    if (bytes.size < 112 || !bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(100, 101, 120, 10)))
                        throw ExecutionException("Invalid/truncated DEX header: ${entry.name}")
                    val expectedClasses = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(96)
                    if (expectedClasses < 0) throw ExecutionException("Invalid DEX class count: ${entry.name}")
                    val loader = DexInputPlugin().loadDex(bytes, entry.name)
                    loaders += loader
                    var visitedClasses = 0
                    loader.visitClasses { cls ->
                        visitedClasses++
                        val owner = cls.type
                        if (classes.put(owner, Class(ClassRef(artifact.sha256, owner, entry.name), cls.superType, cls.interfacesTypes.toList(), cls.accessFlags, cls.copy())) != null)
                            throw ExecutionException("Duplicate DEX class $owner")
                        cls.visitFieldsAndMethods({}, { method ->
                            methodCount++
                            val ref = method.methodRef.also { it.load() }
                            val shortId = "${ref.name}(${ref.argTypes.joinToString("")})${ref.returnType}"
                            method.codeReader?.visitInstructions { insn ->
                                instructionCount++
                                if (insn.opcode == Opcode.UNKNOWN) throw ExecutionException(
                                    "Unknown raw instruction in $owner->$shortId at ${insn.offset}")
                                if (insn.opcode == Opcode.CONST_STRING) {
                                    insn.decode(); stringCount++
                                    uses[insn.indexAsString]?.add(StringUseSite(entry.name, owner, shortId, insn.offset, insn.fileOffset, insn.indexAsString))
                                } else if (callKeys.isNotEmpty() && insn.opcode.name.startsWith("INVOKE_")) {
                                    insn.decode()
                                    if (insn.indexType == InsnIndexType.METHOD_REF) {
                                        val target = insn.indexAsMethod.also { it.load() }
                                        val key = "${target.parentClassType}->${target.name}(${target.argTypes.joinToString("")})${target.returnType}"
                                        if (key in callKeys) {
                                            callOwners.getOrPut(key) { linkedSetOf() } += owner
                                            wantedCallSites += DirectCall(MethodId(owner, ref.name, ref.argTypes.toList(), ref.returnType),
                                                MethodId(target.parentClassType, target.name, target.argTypes.toList(), target.returnType), insn.offset)
                                        }
                                    }
                                }
                            }
                        })
                    }
                    if (visitedClasses != expectedClasses) throw ExecutionException("Incomplete DEX scan: ${entry.name} enumerated $visitedClasses of $expectedClasses classes")
                }
            }
        } catch (e: Exception) { close(); throw ExecutionException("Incomplete raw DEX fact scan: ${e.message}", e) }
        scan = ScanResult(classes.mapValues { it.value.ref.dexEntry }, uses,
            ScanStats(classes.size, methodCount, instructionCount, stringCount, (System.nanoTime() - began) / 1_000_000, emptyList()))
        Digests.verify(artifact)
    }

    fun ref(owner: String): ClassRef = classes[owner]?.ref ?: throw ExecutionException("DEX class missing: $owner")
    fun methodRef(id: MethodId) = MethodRef(ref(id.owner), id.name, id.descriptor)
    private fun members(owner: String): Pair<List<Field>, List<Method>> = members.getOrPut(owner) {
        val cls = classes[owner] ?: throw ExecutionException("DEX class missing: $owner")
        val fields = mutableListOf<Field>(); val methods = mutableListOf<Method>()
        cls.data.visitFieldsAndMethods({ fields += Field(owner, it.name, it.type, it.accessFlags) }, { method ->
            val r = method.methodRef.also { it.load() }
            methods += Method(MethodId(owner, r.name, r.argTypes.toList(), r.returnType), method.accessFlags, method.codeReader?.copy())
        })
        fields to methods
    }
    fun fields(owner: String) = members(owner).first
    fun methods(owner: String) = members(owner).second
    fun method(id: MethodId): Method? = if (id.owner in classes) methods(id.owner).singleOrNull { it.id == id } else null
    fun method(ref: MethodRef): Method? = if (ref.owner.descriptor in classes)
        methods(ref.owner.descriptor).singleOrNull { it.id.name == ref.name && it.id.descriptor == ref.descriptor } else null
    fun trace(method: Method): RawTrace = traces.getOrPut(method.id.key) { RawTrace.read(method) }
    fun isSubtype(type: String, parent: String): Boolean {
        val seen = mutableSetOf<String>(); val queue = ArrayDeque<String>(); queue += type
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst(); if (!seen.add(current)) continue
            if (current == parent) return true
            classes[current]?.let { it.parent?.let(queue::add); queue.addAll(it.interfaces) }
        }
        return false
    }
    fun implementations(parent: String) = implementations.getOrPut(parent) {
        classes.values.filter { it.flags and (0x200 or 0x400) == 0 && isSubtype(it.ref.descriptor, parent) }
    }
    fun inheritedMethod(owner: String, name: String, descriptor: String): Method? {
        var current: String? = owner; val seen = mutableSetOf<String>()
        while (current != null && current in classes && seen.add(current)) {
            methods(current).singleOrNull { it.id.name == name && it.id.descriptor == descriptor }?.let { return it }
            current = classes[current]?.parent
        }
        return null
    }
    override fun close() { loaders.forEach { it.close() }; loaders.clear() }
}
