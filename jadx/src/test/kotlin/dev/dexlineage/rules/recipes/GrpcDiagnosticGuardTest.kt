package dev.dexlineage.rules.recipes

import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import dev.dexlineage.rules.recipes.GrpcDiagnosticGuard.Instruction
import jadx.api.plugins.input.insns.Opcode
import org.junit.jupiter.api.Test
import kotlin.test.*

class GrpcDiagnosticGuardTest {
    private val string = "Ljava/lang/String;"
    private val objectType = "Ljava/lang/Object;"
    private val exception = "Ljava/lang/IllegalArgumentException;"
    private val builder = "Ljava/lang/StringBuilder;"
    private val formatter = MethodId("Lformat;", "format", listOf(string, "[$objectType"), string)
    private val array = Value.Array(6)
    private val formatCall = CallEvent(11, formatter, null, listOf(Value.Parameter(1, string), array), emptyMap(),
        mapOf(array to mapOf(0 to Value.Parameter(2, objectType))), emptyMap())
    private val constructor = CallEvent(15, MethodId(exception, "<init>", listOf(string), "V"),
        Value.Allocation(3, exception), listOf(Value.Invocation(11, formatter, null, formatCall.args)), emptyMap(), emptyMap(), emptyMap())
    private val guard = RawTrace(true, null, listOf(formatCall, constructor), emptyList(), emptyList(), emptyMap())
    private val instructions = listOf(
        Instruction(Opcode.IF_EQZ, 0, 3, listOf(2)), Instruction(Opcode.RETURN_VOID, 2, 0, emptyList()),
        Instruction(Opcode.NEW_INSTANCE, 3, 0, listOf(2), exception), Instruction(Opcode.NEW_ARRAY, 6, 0, listOf(0, 0), "[$objectType"),
        Instruction(Opcode.INVOKE_STATIC, 11, 0, listOf(3, 0)), Instruction(Opcode.MOVE_RESULT, 14, 0, listOf(3)),
        Instruction(Opcode.INVOKE_DIRECT, 15, 0, listOf(2, 3)), Instruction(Opcode.THROW, 18, 0, listOf(2)))

    @Test fun `a guard requires both terminal error shape and an inspected formatter`() {
        assertTrue(GrpcDiagnosticGuard.guardBody(guard, instructions, 2) { it == formatter })
        assertFalse(GrpcDiagnosticGuard.guardBody(guard, instructions, 2) { false })
        assertFalse(GrpcDiagnosticGuard.guardBody(guard, instructions, 3) { true })
        assertFalse(GrpcDiagnosticGuard.guardBody(guard.copy(writes = listOf(
            WriteEvent(9, Field("LsideEffect;", "value", objectType), null, Value.Parameter(2, objectType)))), instructions, 2) { true })
        assertFalse(GrpcDiagnosticGuard.guardBody(guard, instructions + Instruction(Opcode.NEW_INSTANCE, 20, 0, listOf(1), "Ldescriptor;"), 2) { true })
        assertFalse(GrpcDiagnosticGuard.guardBody(guard.copy(calls = listOf(formatCall.copy(arrays = mapOf(array to mapOf(0 to Value.Unknown))), constructor)), instructions, 2) { true })
    }

    @Test fun `formatter proof rejects application callbacks allocations and field effects`() {
        val render = MethodId(builder, "toString", emptyList(), string)
        val instance = Value.Allocation(1, builder)
        val call = CallEvent(8, render, instance, emptyList(), emptyMap(), emptyMap(), emptyMap())
        val pure = RawTrace(true, null, listOf(call), emptyList(), listOf(ReturnEvent(10,
            Value.Invocation(8, render, instance, emptyList()))), emptyMap())
        val body = listOf(Instruction(Opcode.NEW_INSTANCE, 1, 0, listOf(0), builder))
        assertTrue(GrpcDiagnosticGuard.formatterBody(pure, body))
        assertFalse(GrpcDiagnosticGuard.formatterBody(pure.copy(calls = pure.calls + call.copy(method = formatter)), body))
        assertFalse(GrpcDiagnosticGuard.formatterBody(pure, body + Instruction(Opcode.NEW_INSTANCE, 2, 0, listOf(1), "Ldescriptor;")))
        assertFalse(GrpcDiagnosticGuard.formatterBody(pure, body + Instruction(Opcode.SGET, 2, 0, listOf(1), fieldOwner = "Lapplication;")))
        assertFalse(GrpcDiagnosticGuard.formatterBody(pure.copy(complete = false), body))
    }
}
