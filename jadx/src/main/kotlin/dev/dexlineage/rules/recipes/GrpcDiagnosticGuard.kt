package dev.dexlineage.rules.recipes

import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode

/** Finite effect proof for a boolean guard whose only failure effect is a formatted exception. */
internal object GrpcDiagnosticGuard {
    private const val STRING = "Ljava/lang/String;"
    private const val OBJECT = "Ljava/lang/Object;"
    private const val BUILDER = "Ljava/lang/StringBuilder;"
    private const val EXCEPTION = "Ljava/lang/IllegalArgumentException;"
    internal data class Instruction(val op: Opcode, val offset: Int, val target: Int, val regs: List<Int>,
        val type: String? = null, val fieldOwner: String? = null)

    fun accepts(s: DexFactSession, call: CallEvent): Boolean {
        if (call.receiver != null || call.method.args != listOf("Z", STRING, OBJECT) || call.method.result != "V") return false
        return s.cachedRecipe("grpc-diagnostic-guard:${call.method.key}") {
            val method = s.method(call.method)
            if (method == null || method.flags and 8 == 0 || method.code == null || method.code.tries.isNotEmpty()) false
            else {
                val start = method.code.argsStartReg.takeIf { it >= 0 } ?: (method.code.registersCount - 3)
                guardBody(s.trace(method), instructions(method), start) { formatter ->
                    val body = s.method(formatter)
                    body != null && body.flags and 8 != 0 && formatterBody(s.trace(body), instructions(body))
                }
            }
        }
    }

    private fun instructions(method: Method): List<Instruction> = buildList {
        method.code?.visitInstructions { i ->
            i.decode()
            add(Instruction(i.opcode, i.offset, i.target, (0 until i.regsCount).map(i::getReg),
                if (i.indexType == InsnIndexType.TYPE_REF) i.indexAsType else null,
                if (i.indexType == InsnIndexType.FIELD_REF) i.indexAsField.parentClassType else null))
        }
    }

    internal fun guardBody(trace: RawTrace, raw: List<Instruction>, conditionRegister: Int,
        formatterProven: (MethodId) -> Boolean): Boolean {
        if (!trace.complete || trace.writes.isNotEmpty() || trace.calls.size != 2) return false
        val instructions = raw.filter { it.op != Opcode.NOP }
        val first = instructions.firstOrNull() ?: return false
        if (first.op !in setOf(Opcode.IF_EQZ, Opcode.IF_NEZ) || first.regs != listOf(conditionRegister) || instructions.size < 4) return false
        if (instructions.count { it.op.name.startsWith("IF") } != 1 || instructions.count { it.op == Opcode.RETURN_VOID } != 1 || instructions.count { it.op == Opcode.THROW } != 1) return false
        val normal = if (first.op == Opcode.IF_NEZ) first.target else instructions[1].offset
        val failure = if (first.op == Opcode.IF_EQZ) first.target else instructions[1].offset
        if (instructions.singleOrNull { it.offset == normal }?.op != Opcode.RETURN_VOID) return false
        val error = instructions.filter { it != first && it.offset != normal }
        if (error.firstOrNull()?.offset != failure || error.lastOrNull()?.op != Opcode.THROW) return false
        if (error.any { it.op.name.startsWith("IF") || it.op in setOf(Opcode.GOTO, Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH, Opcode.RETURN, Opcode.RETURN_VOID, Opcode.UNKNOWN) }) return false
        val allocations = error.filter { it.op == Opcode.NEW_INSTANCE }
        if (allocations.size != 1 || allocations.single().type != EXCEPTION) return false
        val format = trace.calls.singleOrNull { it.receiver == null && it.method.args == listOf(STRING, "[$OBJECT") && it.method.result == STRING } ?: return false
        if (format.args.firstOrNull() != Value.Parameter(1, STRING)) return false
        val array = format.args.getOrNull(1) as? Value.Array ?: return false
        if (format.arrays[array] != mapOf(0 to Value.Parameter(2, OBJECT))) return false
        val constructor = trace.calls.singleOrNull { it.method.owner == EXCEPTION && it.method.name == "<init>" && it.method.args == listOf(STRING) && it.method.result == "V" } ?: return false
        val allocated = constructor.receiver as? Value.Allocation ?: return false
        if (allocated.site != allocations.single().offset || allocated.type != EXCEPTION || constructor.offset != error.getOrNull(error.lastIndex - 1)?.offset) return false
        if (error.last().regs != allocations.single().regs) return false
        val formatted = constructor.args.singleOrNull() as? Value.Invocation ?: return false
        return formatted.site == format.offset && formatted.method == format.method && formatterProven(format.method)
    }

    internal fun formatterBody(trace: RawTrace, instructions: List<Instruction>): Boolean {
        if (!trace.complete || trace.writes.isNotEmpty() || trace.returns.isEmpty()) return false
        if (instructions.any { it.op == Opcode.NEW_INSTANCE && it.type != BUILDER }) return false
        if (instructions.any { it.fieldOwner != null && it.fieldOwner != "Ljava/util/logging/Level;" }) return false
        if (trace.calls.any { !formattingCall(it.method) }) return false
        return trace.returns.all { returned ->
            val value = returned.value as? Value.Invocation
            value != null && value.method == MethodId(BUILDER, "toString", emptyList(), STRING)
        }
    }

    private fun formattingCall(method: MethodId): Boolean {
        val signature = method.name + method.descriptor
        return when (method.owner) {
            STRING -> signature in setOf("valueOf($OBJECT)$STRING", "length()I", "indexOf(${STRING}I)I", "concat($STRING)$STRING")
            OBJECT -> signature in setOf("toString()$STRING", "getClass()Ljava/lang/Class;")
            "Ljava/lang/Class;" -> signature == "getName()$STRING"
            "Ljava/lang/System;" -> signature == "identityHashCode($OBJECT)I"
            "Ljava/lang/Integer;" -> signature == "toHexString(I)$STRING"
            BUILDER -> signature in setOf("<init>()V", "<init>($STRING)V", "<init>(I)V", "append($STRING)$BUILDER",
                "append($OBJECT)$BUILDER", "append(C)$BUILDER", "append(Ljava/lang/CharSequence;II)$BUILDER", "toString()$STRING")
            "Ljava/util/logging/Logger;" -> signature in setOf("getLogger($STRING)Ljava/util/logging/Logger;",
                "logp(Ljava/util/logging/Level;$STRING$STRING${STRING}Ljava/lang/Throwable;)V")
            else -> false
        }
    }
}
