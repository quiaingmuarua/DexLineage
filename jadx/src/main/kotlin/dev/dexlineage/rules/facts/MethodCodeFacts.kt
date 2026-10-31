package dev.dexlineage.rules.facts

import dev.dexlineage.rules.facts.DexFactSession.*
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode

/** A compact control-shape snapshot used by finite method predicates, not a second DEX API. */
internal data class CodeInstruction(val op: String, val offset: Int, val target: Int, val regs: List<Int>,
    val type: String? = null, val fieldOwner: String? = null)
internal data class DirectCallSite(val offset: Int, val method: MethodId, val isStatic: Boolean)
internal data class MethodControlShape(val hasCode: Boolean, val argumentStartRegister: Int,
    val hasExceptionHandlers: Boolean, val instructions: List<CodeInstruction>) {
    val straightLine: Boolean get() = hasCode && !hasExceptionHandlers && instructions.none {
        it.op.startsWith("IF") || it.op in setOf("GOTO", "PACKED_SWITCH", "SPARSE_SWITCH")
    }
}

/** Existing lower-level capabilities: direct invocation identities, static reads, and control shape. */
internal object MethodCodeFacts {
    fun callSites(method: Method): List<DirectCallSite> = buildList {
        method.code?.visitInstructions { i ->
            if (i.opcode.name.startsWith("INVOKE_")) {
                i.decode()
                if (i.indexType == InsnIndexType.METHOD_REF) {
                    val ref = i.indexAsMethod.also { it.load() }
                    add(DirectCallSite(i.offset, MethodId(ref.parentClassType, ref.name, ref.argTypes.toList(), ref.returnType),
                        i.opcode in setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE)))
                }
            }
        }
    }
    fun invocations(method: Method): Set<MethodId> = buildSet {
        method.code?.visitInstructions { i ->
            if (i.opcode.name.startsWith("INVOKE_")) {
                i.decode()
                if (i.indexType == InsnIndexType.METHOD_REF) {
                    val ref = i.indexAsMethod.also { it.load() }
                    add(MethodId(ref.parentClassType, ref.name, ref.argTypes.toList(), ref.returnType))
                }
            }
        }
    }

    fun staticReads(method: Method): List<Field> = buildList {
        method.code?.visitInstructions { i ->
            if (i.opcode == Opcode.SGET) {
                i.decode(); val field = i.indexAsField
                add(Field(field.parentClassType, field.name, field.type))
            }
        }
    }

    fun controlShape(method: Method): MethodControlShape {
        val code = method.code ?: return MethodControlShape(false, -1, false, emptyList())
        val words = method.id.args.sumOf { if (it in setOf("J", "D")) 2 else 1 } + if (method.flags and 8 == 0) 1 else 0
        val start = code.argsStartReg.takeIf { it >= 0 } ?: code.registersCount - words
        val instructions = buildList {
            code.visitInstructions { i ->
                i.decode()
                add(CodeInstruction(i.opcode.name, i.offset, i.target, (0 until i.regsCount).map(i::getReg),
                    if (i.indexType == InsnIndexType.TYPE_REF) i.indexAsType else null,
                    if (i.indexType == InsnIndexType.FIELD_REF) i.indexAsField.parentClassType else null))
            }
        }
        return MethodControlShape(true, start, code.tries.isNotEmpty(), instructions)
    }
}
