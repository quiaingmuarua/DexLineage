package dev.dexlineage.rules

import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import jadx.api.plugins.input.data.ICodeReader
import jadx.api.plugins.input.data.IMethodRef
import jadx.api.plugins.input.data.ITry
import jadx.api.plugins.input.data.ICatch
import jadx.api.plugins.input.insns.*
import jadx.api.plugins.input.insns.custom.ISwitchPayload
import org.junit.jupiter.api.Test
import java.lang.reflect.Proxy
import java.util.function.Consumer
import kotlin.test.*

class CallSlicesTest {
    private val factory = MethodId("Lfactory;", "make", listOf("Ljava/lang/String;", "[Ljava/lang/Object;"), "Ljava/lang/Object;")

    @Test fun `switch uses real relative case targets and keeps branch arrays separate`() {
        val instructions = listOf(
            i(Opcode.NOP, 0), i(Opcode.PACKED_SWITCH, 2, listOf(7), target = 40),
            i(Opcode.RETURN_VOID, 5),
            i(Opcode.CONST_STRING, 10, listOf(0), text = "first"),
            i(Opcode.CONST_CLASS, 12, listOf(1), type = "LchildA;"),
            i(Opcode.FILLED_NEW_ARRAY, 14, listOf(1)), i(Opcode.MOVE_RESULT, 17, listOf(2)), i(Opcode.GOTO, 18, target = 32),
            i(Opcode.CONST_STRING, 20, listOf(0), text = "second"),
            i(Opcode.CONST_CLASS, 22, listOf(1), type = "LchildB;"),
            i(Opcode.FILLED_NEW_ARRAY, 24, listOf(1)), i(Opcode.MOVE_RESULT, 27, listOf(2)), i(Opcode.GOTO, 28, target = 32),
            i(Opcode.INVOKE_STATIC, 32, listOf(0, 2), method = factory), i(Opcode.MOVE_RESULT, 35, listOf(0)), i(Opcode.RETURN, 36, listOf(0)),
            i(Opcode.PACKED_SWITCH_PAYLOAD, 40, keys = intArrayOf(3, 9), deltas = intArrayOf(8, 18)))
        val method = method(instructions)
        assertFalse(RawTrace.read(method).complete, "Existing strategy control-flow support remains unchanged")
        val slices = CallSlices.read(method)
        assertTrue(slices.uncertainties.isEmpty())
        val pairs = slices.paths.flatMap { path -> path.calls.map { call ->
            assertEquals(call.offset, (path.returns.single().value as Value.Invocation).site)
            (call.args[0] as Value.Text).value to (call.arrays.getValue(call.args[1] as Value.Array).getValue(0) as Value.ClassLiteral).type
        } }.toSet()
        assertEquals(setOf("first" to "LchildA;", "second" to "LchildB;"), pairs)
    }

    @Test fun `unassigned slots and escaped arrays remain unknown at the later call`() {
        val mutate = MethodId("Lhelper;", "mutate", listOf("[Ljava/lang/Object;"), "V")
        val slices = CallSlices.read(method(listOf(
            i(Opcode.CONST, 0, listOf(0), literal = 2), i(Opcode.NEW_ARRAY, 1, listOf(1, 0), type = "[Ljava/lang/Object;"),
            i(Opcode.CONST_STRING, 3, listOf(2), text = "value"), i(Opcode.CONST, 5, listOf(3), literal = 0),
            i(Opcode.APUT_OBJECT, 6, listOf(2, 1, 3)),
            i(Opcode.INVOKE_STATIC, 8, listOf(1), method = mutate),
            i(Opcode.INVOKE_STATIC, 11, listOf(2, 1), method = factory), i(Opcode.MOVE_RESULT, 14, listOf(0)), i(Opcode.RETURN, 15, listOf(0)))))
        val calls = slices.paths.single().calls; val array = calls[0].args.single() as Value.Array
        assertEquals(mapOf(0 to Value.Text("value"), 1 to Value.Unknown), calls[0].arrays[array])
        assertEquals(mapOf(0 to Value.Unknown, 1 to Value.Unknown, -1 to Value.Unknown), calls[1].arrays[array])
    }

    @Test fun `unknown array index cannot preserve a previous deterministic element`() {
        val slices = CallSlices.read(method(listOf(
            i(Opcode.CONST_STRING, 0, listOf(0), text = "known"), i(Opcode.FILLED_NEW_ARRAY, 2, listOf(0)), i(Opcode.MOVE_RESULT, 5, listOf(1)),
            i(Opcode.APUT_OBJECT, 6, listOf(0, 1, 7)), i(Opcode.INVOKE_STATIC, 8, listOf(0, 1), method = factory),
            i(Opcode.MOVE_RESULT, 11, listOf(0)), i(Opcode.RETURN, 12, listOf(0)))))
        val call = slices.paths.single().calls.single()
        assertEquals(mapOf(0 to Value.Unknown, -1 to Value.Unknown), call.arrays[call.args[1]])
    }

    @Test fun `loop uncertainty is scoped to reachable calls and keeps other return paths`() {
        val slices = CallSlices.read(method(listOf(
            i(Opcode.IF_EQZ, 0, listOf(7), target = 10),
            i(Opcode.GOTO, 2, target = 2),
            i(Opcode.CONST_STRING, 10, listOf(0), text = "stable"), i(Opcode.CONST, 12, listOf(1), literal = 0),
            i(Opcode.INVOKE_STATIC, 13, listOf(0, 1), method = factory), i(Opcode.MOVE_RESULT, 16, listOf(0)), i(Opcode.RETURN, 17, listOf(0)))))
        assertTrue(slices.paths.any { it.complete && it.returns.isNotEmpty() })
        assertEquals(emptySet(), slices.uncertainties.single().relevantCallOffsets)
    }

    @Test fun `refilling an escaped array cannot restore a trusted snapshot`() {
        val mutate = MethodId("Lhelper;", "remember", listOf("[Ljava/lang/Object;"), "V")
        val path = CallSlices.read(method(listOf(
            i(Opcode.CONST_STRING, 0, listOf(0), text = "old"), i(Opcode.FILLED_NEW_ARRAY, 2, listOf(0)), i(Opcode.MOVE_RESULT, 5, listOf(1)),
            i(Opcode.INVOKE_STATIC, 6, listOf(1), method = mutate),
            i(Opcode.CONST_CLASS, 9, listOf(2), type = "Lrefilled;"), i(Opcode.CONST, 11, listOf(3), literal = 0),
            i(Opcode.APUT_OBJECT, 12, listOf(2, 1, 3)),
            i(Opcode.INVOKE_STATIC, 14, listOf(0, 1), method = factory), i(Opcode.MOVE_RESULT, 17, listOf(0)), i(Opcode.RETURN, 18, listOf(0))))).paths.single()
        val call = path.calls.last(); val snapshot = call.arrays.getValue(call.args[1] as Value.Array)
        assertTrue(-1 in snapshot)
        assertTrue(snapshot.values.all { it == Value.Unknown })
    }

    @Test fun `post-call writes and forwarding the result retain the original call relationship`() {
        val forward = MethodId("Lhelper;", "forward", listOf("Ljava/lang/Object;"), "Ljava/lang/Object;")
        val path = CallSlices.read(method(listOf(
            i(Opcode.CONST_STRING, 0, listOf(0), text = "info"), i(Opcode.CONST_CLASS, 2, listOf(1), type = "Lfirst;"),
            i(Opcode.FILLED_NEW_ARRAY, 4, listOf(1)), i(Opcode.MOVE_RESULT, 7, listOf(2)),
            i(Opcode.INVOKE_STATIC, 8, listOf(0, 2), method = factory), i(Opcode.MOVE_RESULT, 11, listOf(3)),
            i(Opcode.CONST_CLASS, 12, listOf(1), type = "Lchanged;"), i(Opcode.CONST, 14, listOf(4), literal = 0),
            i(Opcode.APUT_OBJECT, 15, listOf(1, 2, 4)),
            i(Opcode.INVOKE_STATIC, 17, listOf(3), method = forward), i(Opcode.MOVE_RESULT, 20, listOf(3)), i(Opcode.RETURN, 21, listOf(3))))).paths.single()
        val call = path.calls.first(); val array = call.args[1] as Value.Array
        assertEquals(Value.ClassLiteral("Lfirst;"), call.arrays.getValue(array)[0])
        assertEquals(setOf(15, 17), path.arrayEffects.filter { it.array == array && call.offset in it.precedingCalls }.map { it.offset }.toSet())
    }

    @Test fun `exception before a relevant call cannot be scoped away by an opaque catch return`() {
        val catcher = proxy<ICatch> { name, _ -> when (name) {
            "getHandlers" -> intArrayOf(20); "getCatchAllHandler" -> -1; "getTypes" -> arrayOf("Ljava/lang/Exception;"); else -> null
        } }
        val attempt = proxy<ITry> { name, _ -> when (name) { "getStartOffset" -> 0; "getEndOffset" -> 2; "getCatch" -> catcher; else -> null } }
        val slices = CallSlices.read(method(listOf(
            i(Opcode.CONST_STRING, 0, listOf(0), text = "schema"), i(Opcode.CONST, 2, listOf(1), literal = 0),
            i(Opcode.INVOKE_STATIC, 4, listOf(0, 1), method = factory), i(Opcode.MOVE_RESULT, 7, listOf(0)), i(Opcode.RETURN, 8, listOf(0)),
            i(Opcode.RETURN, 20, listOf(6))), listOf(attempt)))
        assertTrue(slices.paths.any { it.complete })
        assertTrue(slices.uncertainties.isNotEmpty())
        assertTrue(slices.uncertainties.all { 4 in it.relevantCallOffsets.orEmpty() }, "Normal continuation is relevant even if the catch never calls the factory")
    }

    private fun method(insns: List<InsnData>, tries: List<ITry> = emptyList()) = Method(MethodId("Lsample;", "dispatch", emptyList(), "Ljava/lang/Object;"), 8,
        proxy<ICodeReader> { name, args -> when (name) {
            "getArgsStartReg" -> -1; "getRegistersCount" -> 8; "getUnitsCount" -> 100; "getTries" -> tries
            "visitInstructions" -> { @Suppress("UNCHECKED_CAST") val consumer = args!![0] as Consumer<InsnData>; insns.forEach(consumer::accept); null }
            else -> null
        } })
    private fun i(op: Opcode, offset: Int, regs: List<Int> = emptyList(), target: Int = 0,
        literal: Long = 0, text: String? = null, type: String? = null, method: MethodId? = null,
        keys: IntArray? = null, deltas: IntArray? = null): InsnData = proxy { name, args -> when (name) {
        "getOpcode" -> op; "getOffset" -> offset; "getRegsCount" -> regs.size; "getReg" -> regs[args!![0] as Int]
        "getResultReg" -> -1; "getLiteral" -> literal; "getTarget" -> target; "getIndexAsString" -> text; "getIndexAsType" -> type
        "getPayload" -> if (keys == null) null else proxy<ISwitchPayload> { key, _ -> when (key) { "getKeys" -> keys; "getTargets" -> deltas; "getSize" -> keys.size; else -> null } }
        "getIndexType" -> when { method != null -> InsnIndexType.METHOD_REF; type != null -> InsnIndexType.TYPE_REF; else -> InsnIndexType.NONE }
        "getIndexAsMethod" -> proxy<IMethodRef> { key, _ -> when (key) {
            "getParentClassType" -> method!!.owner; "getName" -> method!!.name; "getArgTypes" -> method!!.args; "getReturnType" -> method!!.result; else -> null
        } }
        else -> null
    } }
    private inline fun <reified T> proxy(crossinline call: (String, Array<out Any?>?) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, method, args -> call(method.name, args) } as T
}
