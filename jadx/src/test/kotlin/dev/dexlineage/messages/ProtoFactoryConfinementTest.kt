package dev.dexlineage.messages

import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class ProtoFactoryConfinementTest {
    private val owner = "Lmetadata;"
    private val self = Value.Parameter(-1, owner)
    private val array = Value.Parameter(2, "[Ljava/lang/Object;")
    private fun call(id: MethodId, receiver: Value? = null, vararg args: Value) =
        CallEvent(10, id, receiver, args.toList(), emptyMap(), emptyMap(), emptyMap())
    private fun check(calls: List<CallEvent>, writes: List<WriteEvent> = emptyList()) =
        ProtoRecipe.constructorConfined(RawTrace(true, null, calls, writes, emptyList(), emptyMap()), owner)

    @Test fun `precise object construction and string flags reads are confined`() {
        assertTrue(check(listOf(
            call(MethodId("Ljava/lang/Object;", "<init>", emptyList(), "V"), self),
            call(MethodId("Ljava/lang/Object;", "getClass", emptyList(), "Ljava/lang/Class;"), array),
            call(MethodId("Ljava/lang/String;", "charAt", listOf("I"), "C"), Value.Parameter(1, "Ljava/lang/String;"), Value.Unknown)),
            listOf(WriteEvent(5, Field(owner, "objects", "[Ljava/lang/Object;"), self, array))))
    }

    @Test fun `opaque receiver array argument and unknown reference escape are rejected`() {
        assertFalse(check(listOf(call(MethodId("Lhelper;", "touch", listOf("Ljava/lang/Object;"), "V"), null, self))))
        assertFalse(check(listOf(call(MethodId(owner, "mutate", emptyList(), "V"), self))))
        assertFalse(check(listOf(call(MethodId("Lhelper;", "touch", listOf("[Ljava/lang/Object;"), "V"), null, array))))
        assertFalse(check(listOf(call(MethodId("Lhelper;", "getClass", listOf("Ljava/lang/Object;"), "V"), null, self))))
        assertFalse(check(listOf(call(MethodId("Lhelper;", "touch", listOf("Ljava/lang/Object;"), "V"), null, Value.Unknown))))
    }

    @Test fun `array can only be stored on this metadata object`() {
        assertFalse(check(emptyList(), listOf(WriteEvent(3, Field("Lglobal;", "array", "[Ljava/lang/Object;"), null, array))))
        assertFalse(check(emptyList(), listOf(WriteEvent(3, Field(owner, "self", owner), self, self))))
        assertFalse(check(listOf(call(MethodId("Lhelper;", "touch", listOf("[Ljava/lang/Object;"), "V"), null,
            Value.FieldRead(Field(owner, "objects", "[Ljava/lang/Object;"), self)))))
    }
}
