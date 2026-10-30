package dev.dexlineage.apk

import dev.dexlineage.io.Digests
import dev.dexlineage.io.ExecutionException
import dev.dexlineage.io.ValidationException
import dev.dexlineage.io.requireInput
import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.DexFactSession
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode

/** Plain source facts for investigation. These are neither matching results nor naming authority. */
data class ResearchFieldFact(val name: String, val type: String, val accessFlags: Int)
data class ResearchMethodReference(val ownerDescriptor: String, val name: String, val descriptor: String)
data class ResearchFieldReference(val ownerDescriptor: String, val name: String, val type: String)
data class ResearchCallSite(val target: ResearchMethodReference, val opcode: String, val codeUnitOffset: Int, val fileOffset: Int)
data class ResearchFieldAccess(val target: ResearchFieldReference, val opcode: String, val codeUnitOffset: Int, val fileOffset: Int)
data class ResearchMethodFact(val ref: MethodRef, val accessFlags: Int, val hasCode: Boolean,
    val strings: List<StringUseSite>, val calls: List<ResearchCallSite>, val fieldAccesses: List<ResearchFieldAccess>,
    val diagnostics: List<String>)
data class ResearchClassFacts(val ref: ClassRef, val accessFlags: Int, val superType: String?, val interfaces: List<String>,
    val fields: List<ResearchFieldFact>, val methods: List<ResearchMethodFact>)
data class ApkResearchFacts(val classes: List<ResearchClassFacts>, val scan: ScanStats, val elapsedMillis: Long)

/** Batch exact source addresses solely for research; the rule engine still searches the whole APK. */
object ApkResearchReader {
    fun read(artifact: Artifact, selected: Collection<ClassRef>): ApkResearchFacts {
        requireInput(selected.isNotEmpty() && selected.distinct().size == selected.size, "Expected distinct research class references")
        requireInput(selected.all { it.apkSha256 == artifact.sha256 }, "Research class belongs to another APK")
        val started = System.nanoTime()
        try {
            DexFactSession(artifact, emptySet()).use { session ->
                val classes = selected.sortedBy { it.descriptor }.map { ref ->
                    val cls = session.classes[ref.descriptor]
                        ?: throw ValidationException("Research class absent from corpus APK: $ref")
                    requireInput(cls.ref == ref, "Research class/DEX identity absent from corpus APK: $ref")
                    val fields = session.fields(ref.descriptor).map { ResearchFieldFact(it.name, it.type, it.flags) }
                        .sortedWith(compareBy({ it.name }, { it.type }))
                    val methods = session.methods(ref.descriptor).map { method ->
                        val strings = mutableListOf<StringUseSite>()
                        val calls = mutableListOf<ResearchCallSite>()
                        val accesses = mutableListOf<ResearchFieldAccess>()
                        val diagnostics = mutableListOf<String>()
                        method.code?.visitInstructions { insn ->
                            when {
                                insn.opcode == Opcode.UNKNOWN -> throw ExecutionException(
                                    "Unknown raw instruction in ${ref.descriptor}->${method.id.shortId} at ${insn.offset}")
                                insn.opcode == Opcode.CONST_STRING -> {
                                    insn.decode()
                                    strings += StringUseSite(ref.dexEntry, ref.descriptor, method.id.shortId,
                                        insn.offset, insn.fileOffset, insn.indexAsString)
                                }
                                insn.opcode.name.startsWith("INVOKE_") -> {
                                    insn.decode()
                                    if (insn.indexType == InsnIndexType.METHOD_REF) {
                                        val target = insn.indexAsMethod.also { it.load() }
                                        calls += ResearchCallSite(ResearchMethodReference(target.parentClassType, target.name,
                                            "(${target.argTypes.joinToString("")})${target.returnType}"), insn.opcode.name, insn.offset, insn.fileOffset)
                                    } else diagnostics += "${insn.opcode.name} at ${insn.offset} has ${insn.indexType}; not a direct method-reference call"
                                }
                                else -> {
                                    insn.decode()
                                    if (insn.indexType == InsnIndexType.FIELD_REF) {
                                        val target = insn.indexAsField
                                        accesses += ResearchFieldAccess(ResearchFieldReference(target.parentClassType, target.name, target.type),
                                            insn.opcode.name, insn.offset, insn.fileOffset)
                                    }
                                }
                            }
                        }
                        ResearchMethodFact(session.methodRef(method.id), method.flags, method.code != null,
                            strings.sortedBy { it.codeUnitOffset }, calls.sortedBy { it.codeUnitOffset },
                            accesses.sortedBy { it.codeUnitOffset }, diagnostics.toList())
                    }.sortedWith(compareBy({ it.ref.name }, { it.ref.descriptor }))
                    ResearchClassFacts(ref, cls.flags, cls.parent, cls.interfaces.sorted(), fields, methods)
                }
                Digests.verify(artifact)
                return ApkResearchFacts(classes, session.scan.stats, (System.nanoTime() - started) / 1_000_000)
            }
        } catch (e: ValidationException) { throw e }
        catch (e: ExecutionException) { throw e }
        catch (e: Exception) { throw ExecutionException("Cannot read source research facts: ${e.message ?: e.javaClass.name}", e) }
    }
}
