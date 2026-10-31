package dev.dexlineage.messages

import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class ProtoMetadataLifetimeTest {
    private val array = Value.Array(4)
    private val method = MethodId("Lbase;", "metadata", listOf("Lmessage;", "Ljava/lang/String;", "[Ljava/lang/Object;"), "Ljava/lang/Object;")
    private val call = CallEvent(20, method, null, listOf(Value.Unknown, Value.Text("info"), array), emptyMap(), emptyMap(), emptyMap())
    private val result = Value.Invocation(call.offset, method, null, call.args)
    private fun path(returned: Value = result, effects: List<ArrayEffect> = emptyList()) =
        RawTrace(true, null, listOf(call), emptyList(), listOf(ReturnEvent(40, returned)), emptyMap(), effects)

    @Test fun `pre-call population is allowed but post-call write invalidates snapshot`() {
        assertNull(ProtoRecipe.metadataLifetimeProblem(path(effects = listOf(ArrayEffect(8, array, emptySet(), "array write"))), call))
        assertNotNull(ProtoRecipe.metadataLifetimeProblem(path(effects = listOf(ArrayEffect(25, array, setOf(20), "array write"))), call))
        assertNotNull(ProtoRecipe.metadataLifetimeProblem(path(effects = listOf(ArrayEffect(30, array, setOf(20), "opaque escape"))), call))
        assertNull(ProtoRecipe.metadataLifetimeProblem(path(effects = listOf(ArrayEffect(25, Value.Array(9), setOf(20), "other array write"))), call))
    }

    @Test fun `opaque forwarding and cached returns remain unknown`() {
        val helper = MethodId("Lhelper;", "forward", listOf("Ljava/lang/Object;"), "Ljava/lang/Object;")
        listOf<Value>(Value.Invocation(25, helper, null, listOf(result)), Value.CallResult(25, helper), Value.Unknown,
            Value.FieldRead(Field("Lcache;", "value", "Ljava/lang/Object;")), Value.Parameter(1, "Ljava/lang/Object;"), Value.Allocation(29, "Lother;")).forEach { returned ->
            assertEquals(ProtoRecipe.MetadataReturn.UNKNOWN, ProtoRecipe.returnRelation(path(returned), call))
        }
    }

    @Test fun `only the direct result or definite unrelated constants can be classified`() {
        assertEquals(ProtoRecipe.MetadataReturn.DIRECT, ProtoRecipe.returnRelation(path(), call))
        assertEquals(ProtoRecipe.MetadataReturn.DIRECT, ProtoRecipe.returnRelation(path(Value.CallResult(20, method)), call))
        listOf(Value.Number(0), Value.Text("unrelated"), Value.ClassLiteral("Lother;")).forEach { returned ->
            assertEquals(ProtoRecipe.MetadataReturn.IGNORED, ProtoRecipe.returnRelation(path(returned), call))
        }
    }
}
