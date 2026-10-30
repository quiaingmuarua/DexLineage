package dev.dexlineage.rules.recipes

import com.google.gson.JsonParser
import dev.dexlineage.io.ExecutionException
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.DexFactSession.MethodId
import org.junit.jupiter.api.Test
import kotlin.test.*

class RpcRelatedTypeTest {
    private val hash = "a".repeat(64)
    private fun binding(descriptor: String = "Ldescriptor;", builder: String = "Lbuilder;", declaration: String = "Lmarshaller;") =
        RpcRecipe.Binding(MethodId("Lstub;", "rpc", emptyList(), "Ljava/lang/Object;"), "Lrequest;", "Lresponse;",
            descriptor, builder, declaration, declaration, "LrequestImpl;", "LresponseImpl;", emptySet(), 12)

    private fun select(bindings: List<RpcRecipe.Binding>, role: String, incomplete: Boolean = false,
        isInterface: (String) -> Boolean = { true }, isSubtype: (String, String) -> Boolean = { _, _ -> true }) =
        RpcRecipe.selectRelatedTypes(bindings, incomplete, role, isInterface, isSubtype)

    @Test fun `descriptor comes from allocation and marshaller from declared interface`() {
        val value = binding()
        assertEquals("Ldescriptor;", select(listOf(value), "descriptor").single().type)
        assertNotEquals(value.method.result, select(listOf(value), "descriptor").single().type)
        assertEquals("Lbuilder;", select(listOf(value), "builder").single().type)
        assertEquals("Lmarshaller;", select(listOf(value), "marshaller").single().type)
    }

    @Test fun `same method incomplete construction cannot publish any related role`() {
        for (role in listOf("descriptor", "builder", "marshaller")) {
            val selected = select(listOf(binding(), binding().copy(offset = 31)), role, incomplete = true)
            assertTrue(selected.all { it.status == MatchStatus.UNKNOWN })
            assertEquals(ResolutionStatus.UNKNOWN, resolution(role, selected).status)
        }
    }

    @Test fun `complete distinct types remain ambiguous and repeated same types deduplicate`() {
        for (role in listOf("descriptor", "builder", "marshaller")) {
            assertEquals(ResolutionStatus.UNIQUE, resolution(role, select(listOf(binding(), binding().copy(offset = 31)), role)).status)
            val other = binding("LotherDescriptor;", "LotherBuilder;", "LotherMarshaller;")
            assertEquals(ResolutionStatus.AMBIGUOUS, resolution(role, select(listOf(binding(), other), role)).status)
        }
    }

    @Test fun `bad declaration or implementation poisons all marshaller facts`() {
        val good = binding()
        val unequal = good.copy(responseDeclarationType = "LotherMarshaller;")
        val cases = listOf(
            select(listOf(good, unequal), "marshaller"),
            select(listOf(good), "marshaller", isInterface = { false }),
            select(listOf(good), "marshaller", isSubtype = { implementation, _ -> implementation != "LresponseImpl;" }))
        cases.forEach { facts ->
            assertTrue(facts.all { it.status == MatchStatus.UNKNOWN })
            assertEquals(ResolutionStatus.UNKNOWN, resolution("marshaller", facts).status)
        }
    }

    @Test fun `missing reproducible construction is an execution error not no match`() {
        assertFailsWith<ExecutionException> { select(emptyList(), "descriptor", incomplete = true) }
        assertFailsWith<ExecutionException> { select(emptyList(), "builder") }
    }

    private fun resolution(role: String, selected: List<RpcRecipe.RelatedType>): Resolution {
        val producer = RuleProofs.revision(emptyList(), StrategySpec("messages.rpc-descriptor",
            JsonParser.parseString("{\"service\":\"fixture.Service\",\"rpc\":\"Read\"}").asJsonObject, EntityKind.METHOD))
        val owner = ClassRef(hash, "Lstub;", "classes.dex")
        val method = MethodRef(owner, "rpc", "()Ljava/lang/Object;")
        val proof = RuleProofs.create(hash, producer, "engine", listOf(MatchFact(owner, MatchStatus.PASS,
            listOf(FactorResult("rpc", MatchStatus.PASS, "complete construction")), emptyMap(), method = method)))
        val anchor = SupportAnchor("rpc", EntityRef(owner, method), producer, proof, emptyList())
        val rule = RuleProofs.revision(emptyList(), StrategySpec("messages.rpc-related-type",
            JsonParser.parseString("{\"role\":\"$role\"}").asJsonObject, EntityKind.CLASS, mapOf("descriptor" to "rpc")))
        val facts = selected.map { MatchFact(ClassRef(hash, it.type, "classes.dex"), it.status,
            listOf(FactorResult("rpc-related-type", it.status, it.detail)), emptyMap()) }
        return RuleProofs.create(hash, rule, "engine", facts, mapOf("descriptor" to anchor)).also(RuleProofs::validate)
    }
}
