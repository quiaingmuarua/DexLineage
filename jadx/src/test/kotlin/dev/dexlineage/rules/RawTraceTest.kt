package dev.dexlineage.rules

import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import jadx.api.plugins.input.data.ICodeReader
import jadx.api.plugins.input.data.IFieldRef
import jadx.api.plugins.input.data.IMethodRef
import jadx.api.plugins.input.insns.*
import java.lang.reflect.Proxy
import java.util.function.Consumer
import kotlin.test.*
import org.junit.jupiter.api.Test

class RawTraceTest {
    @Test fun `expression budget keeps a finite result identity without inventing argument constants`() {
        val string = "Ljava/lang/String;"
        val getter = MethodId("Lhelper;", "read", listOf(string), string)
        val factory = MethodId("Ldescriptor;", "name", listOf(string, string), string)
        val instructions = mutableListOf(insn(Opcode.CONST_STRING, 0, listOf(0), text = "nested"))
        repeat(7) { index ->
            instructions += insn(Opcode.INVOKE_STATIC, 2 + index * 4, listOf(0), method = getter)
            instructions += insn(Opcode.MOVE_RESULT, 5 + index * 4, listOf(0))
        }
        instructions += insn(Opcode.CONST_STRING, 32, listOf(1), text = "Read")
        instructions += insn(Opcode.INVOKE_STATIC, 34, listOf(0, 1), method = factory)
        instructions += insn(Opcode.MOVE_RESULT, 37, listOf(0))
        instructions += insn(Opcode.RETURN, 38, listOf(0))
        val trace = RawTrace.read(method(instructions))
        assertTrue(trace.complete)
        assertEquals(Value.CallResult(34, factory), trace.returns.single().value)
        assertIs<Value.Invocation>(trace.calls.last().args.first(), "The argument is not a fabricated literal")
    }

    @Test fun `different branch values are unknown after merge`() {
        val method = method(listOf(
            insn(Opcode.IF_EQZ, 0, listOf(1), target = 6),
            insn(Opcode.CONST_STRING, 2, listOf(0), text = "first"),
            insn(Opcode.GOTO, 4, target = 8),
            insn(Opcode.CONST_STRING, 6, listOf(0), text = "second"),
            insn(Opcode.RETURN, 8, listOf(0))))
        val trace = RawTrace.read(method)
        assertTrue(trace.complete)
        assertEquals(Value.Unknown, trace.returns.single().value)
    }

    @Test fun `DEX final registers account for receiver and wide arguments`() {
        val field = Field("Lsample;", "value", "Ljava/lang/String;")
        val method = method(listOf(insn(Opcode.IPUT, 0, listOf(7, 4), field = field), insn(Opcode.RETURN_VOID, 2)),
            args = listOf("J", "Ljava/lang/String;"), flags = 1, registers = 8)
        val write = RawTrace.read(method).writes.single()
        assertEquals(Value.Parameter(-1, "Lsample;"), write.receiver)
        assertEquals(Value.Parameter(1, "Ljava/lang/String;"), write.value)
    }

    @Test fun `field state stays on its own builder identity`() {
        val factory = MethodId("Ldescriptor;", "builder", emptyList(), "Lbuilder;")
        val build = MethodId("Lbuilder;", "build", emptyList(), "Ldescriptor;")
        val field = Field("Lbuilder;", "request", "Lmarshaller;")
        val trace = RawTrace.read(method(listOf(
            insn(Opcode.INVOKE_STATIC, 0, method = factory), insn(Opcode.MOVE_RESULT, 3, listOf(0)),
            insn(Opcode.INVOKE_STATIC, 4, method = factory), insn(Opcode.MOVE_RESULT, 7, listOf(1)),
            insn(Opcode.CONST, 8, listOf(2), number = 0), insn(Opcode.IPUT, 9, listOf(2, 1), field = field),
            insn(Opcode.INVOKE_VIRTUAL, 11, listOf(0), method = build), insn(Opcode.MOVE_RESULT, 14, listOf(0)),
            insn(Opcode.RETURN, 15, listOf(0)))))
        assertTrue(trace.complete)
        assertTrue(trace.calls.last().fields.isEmpty(), "Another builder's request cannot supply this builder's role")
    }

    @Test fun `unsupported switch is diagnosed rather than treated as no values`() {
        val trace = RawTrace.read(method(listOf(insn(Opcode.PACKED_SWITCH, 0, listOf(0)))))
        assertFalse(trace.complete)
        assertTrue(trace.reason!!.contains("Unsupported"))
    }

    @Test fun `a mutable argument array is unknown after an opaque call`() {
        val mutate = MethodId("Lhelper;", "mutate", listOf("[Ljava/lang/Object;"), "V")
        val log = MethodId("Llogger;", "log", listOf("Ljava/lang/String;", "[Ljava/lang/Object;"), "V")
        val trace = RawTrace.read(method(listOf(
            insn(Opcode.CONST_STRING, 0, listOf(0), text = "component"),
            insn(Opcode.FILLED_NEW_ARRAY, 2, listOf(0)), insn(Opcode.MOVE_RESULT, 5, listOf(1)),
            insn(Opcode.INVOKE_STATIC, 6, listOf(1), method = mutate),
            insn(Opcode.CONST_STRING, 9, listOf(0), text = "format"),
            insn(Opcode.INVOKE_STATIC, 11, listOf(0, 1), method = log), insn(Opcode.RETURN_VOID, 14))))
        val beforeEscape = trace.calls.first(); val array = beforeEscape.args.single() as Value.Array
        assertEquals(Value.Text("component"), beforeEscape.arrays.getValue(array).getValue(0))
        assertEquals(Value.Unknown, trace.calls.last().arrays.getValue(array).getValue(0))
    }

    private fun method(insns: List<InsnData>, args: List<String> = emptyList(), flags: Int = 8, registers: Int = 8): Method {
        val reader = proxy<ICodeReader> { name, callArgs -> when(name) {
            "getArgsStartReg" -> -1
            "getRegistersCount" -> registers
            "getUnitsCount" -> 100
            "getTries" -> emptyList<Any>()
            "visitInstructions" -> { @Suppress("UNCHECKED_CAST") val consumer = callArgs!![0] as Consumer<InsnData>; insns.forEach(consumer::accept); null }
            else -> null
        } }
        return Method(MethodId("Lsample;", "run", args, "Ljava/lang/String;"), flags, reader)
    }
    private fun insn(op: Opcode, offset: Int, regs: List<Int> = emptyList(), target: Int = 0, text: String? = null,
        number: Long = 0, field: Field? = null, method: MethodId? = null): InsnData = proxy { name, args -> when(name) {
        "decode" -> null
        "getOpcode" -> op
        "getOffset" -> offset
        "getRegsCount" -> regs.size
        "getReg" -> regs[args!![0] as Int]
        "getResultReg" -> -1
        "getLiteral" -> number
        "getTarget" -> target
        "getIndexAsString" -> text
        "getIndexType" -> if (field != null) InsnIndexType.FIELD_REF else if (method != null) InsnIndexType.METHOD_REF else InsnIndexType.NONE
        "getIndexAsField" -> proxy<IFieldRef> { key, _ -> when(key) { "getParentClassType" -> field!!.owner; "getName" -> field!!.name; "getType" -> field!!.type; else -> null } }
        "getIndexAsMethod" -> proxy<IMethodRef> { key, _ -> when(key) { "getParentClassType" -> method!!.owner; "getName" -> method!!.name; "getArgTypes" -> method!!.args; "getReturnType" -> method!!.result; else -> null } }
        else -> null
    } }
    private inline fun <reified T> proxy(crossinline call: (String, Array<out Any?>?) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, method, args -> call(method.name, args) } as T
}
