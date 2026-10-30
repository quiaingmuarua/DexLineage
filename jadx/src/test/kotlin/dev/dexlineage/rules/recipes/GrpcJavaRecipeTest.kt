package dev.dexlineage.rules.recipes

import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class GrpcJavaRecipeTest {
    private val string = "Ljava/lang/String;"
    private val builder = "Ljava/lang/StringBuilder;"
    private val instance = Value.Allocation(0, builder)
    private fun trace(tokens: List<Value> = listOf(Value.Parameter(0, string), Value.Text("/"), Value.Parameter(1, string))): RawTrace {
        val init = MethodId(builder, "<init>", emptyList(), "V")
        val append = MethodId(builder, "append", listOf(string), builder)
        val render = MethodId(builder, "toString", emptyList(), string)
        val calls = listOf(CallEvent(1, init, instance, emptyList(), emptyMap(), emptyMap(), emptyMap())) +
            tokens.mapIndexed { index, token -> CallEvent(3 + index * 2, append, instance, listOf(token), emptyMap(), emptyMap(), emptyMap()) } +
            CallEvent(12, render, instance, emptyList(), emptyMap(), emptyMap(), emptyMap())
        return RawTrace(true, null, calls, emptyList(), listOf(ReturnEvent(15, Value.Invocation(12, render, instance, emptyList()))), emptyMap())
    }

    @Test fun `only ordered argument slash argument concatenation proves the name factory`() {
        assertEquals(MatchStatus.PASS, GrpcJavaRecipe.fullMethodNameStatus(trace(), true))
        for (tokens in listOf(
            listOf(Value.Parameter(1, string), Value.Text("/"), Value.Parameter(0, string)),
            listOf(Value.Parameter(0, string), Value.Text(":"), Value.Parameter(1, string)),
            listOf(Value.Text("/")))) {
            assertEquals(MatchStatus.FAIL, GrpcJavaRecipe.fullMethodNameStatus(trace(tokens), true))
        }
    }

    @Test fun `branching and unknown append values cannot assert concatenation order`() {
        assertEquals(MatchStatus.UNKNOWN, GrpcJavaRecipe.fullMethodNameStatus(trace(), false))
        assertEquals(MatchStatus.UNKNOWN, GrpcJavaRecipe.fullMethodNameStatus(trace(listOf(Value.Unknown)), true))
        assertEquals(MatchStatus.UNKNOWN, GrpcJavaRecipe.fullMethodNameStatus(trace().copy(complete = false), true))
        val unsafe = trace().copy(calls = trace().calls + CallEvent(10,
            MethodId(builder, "reverse", emptyList(), builder), instance, emptyList(), emptyMap(), emptyMap(), emptyMap()))
        assertEquals(MatchStatus.UNKNOWN, GrpcJavaRecipe.fullMethodNameStatus(unsafe, true))
        val escape = trace().copy(calls = trace().calls + CallEvent(10,
            MethodId("Lhelper;", "mutate", listOf(builder), "V"), null, listOf(instance), emptyMap(), emptyMap(), emptyMap()))
        assertEquals(MatchStatus.UNKNOWN, GrpcJavaRecipe.fullMethodNameStatus(escape, true))
    }

    @Test fun `unknown construction is scoped only by selector parts actually known`() {
        val ref = MethodRef(ClassRef("a".repeat(64), "Lcaller;", "classes.dex"), "run", "()V")
        val target = GrpcJavaRecipe.Selector("fixture.Service", "Read", "request")
        assertTrue(GrpcJavaRecipe.mayMatch(UnresolvedPath(ref, 2, "unknown"), target))
        assertTrue(GrpcJavaRecipe.mayMatch(UnresolvedPath(ref, 2, "unknown", "fixture.Service"), target))
        assertFalse(GrpcJavaRecipe.mayMatch(UnresolvedPath(ref, 2, "unknown", "other.Service"), target))
        assertFalse(GrpcJavaRecipe.mayMatch(UnresolvedPath(ref, 2, "unknown", rpc = "Write"), target))
        assertFalse(GrpcJavaRecipe.mayMatch(UnresolvedPath(ref, 2, "unknown", role = "response"), target))
    }

    @Test fun `name escaping into an opaque descriptor helper remains a possible construction`() {
        val factory = MethodId("Ldescriptor;", "name", listOf(string, string), string)
        val nameCall = CallEvent(2, factory, null, listOf(Value.Text("fixture.Service"), Value.Text("Read")), emptyMap(), emptyMap(), emptyMap())
        val name = Value.Invocation(2, factory, null, nameCall.args)
        fun body(target: MethodId) = RawTrace(true, null, listOf(nameCall,
            CallEvent(5, target, null, listOf(name), emptyMap(), emptyMap(), emptyMap())), emptyList(), emptyList(), emptyMap())
        val helper = MethodId("Lhelper;", "opaque", listOf(string), "Ldescriptor;")
        assertTrue(GrpcJavaRecipe.potentialConstruction(body(helper), nameCall, "Ldescriptor;", { it == "Lhelper;" }, { false }))
        val applicationWrapper = helper.copy(result = "Ljava/lang/Object;")
        assertTrue(GrpcJavaRecipe.potentialConstruction(body(applicationWrapper), nameCall, "Ldescriptor;", { it == "Lhelper;" }, { false }))
        val mapPut = MethodId("Ljava/util/Map;", "put", listOf("Ljava/lang/Object;", "Ljava/lang/Object;"), "Ljava/lang/Object;")
        assertFalse(GrpcJavaRecipe.potentialConstruction(body(mapPut), nameCall, "Ldescriptor;", { false }, { false }))
        for (receiver in listOf(null, Value.Allocation(0, "Lholder;"))) {
            val escaped = RawTrace(true, null, listOf(nameCall), listOf(
                WriteEvent(5, Field("Lholder;", "saved", string), receiver, name)), emptyList(), emptyMap())
            assertTrue(GrpcJavaRecipe.potentialConstruction(escaped, nameCall, "Ldescriptor;", { it == "Lholder;" }, { false }),
                "Both static and instance field escapes may feed an unsupported later construction")
        }
    }
}
