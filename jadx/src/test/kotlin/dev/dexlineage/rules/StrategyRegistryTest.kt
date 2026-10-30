package dev.dexlineage.rules

import com.google.gson.JsonParser
import dev.dexlineage.io.ValidationException
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import kotlin.test.*
import org.junit.jupiter.api.Test

class StrategyRegistryTest {
    private fun rule(id: String, parameters: String, kind: EntityKind = EntityKind.METHOD, requires: Map<String, String> = emptyMap()) =
        RuleProofs.revision(emptyList(), StrategySpec(id, JsonParser.parseString(parameters).asJsonObject, kind, requires))

    @Test fun `unregistered strategy and extra parameters are rejected`() {
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("messages.guess", "{}")) }
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("messages.rpc-descriptor", "{\"service\":\"sample\",\"rpc\":\"read\",\"expectedOwner\":\"La;\"}")) }
    }
    @Test fun `strategy requires exact dependency roles and result kind`() {
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("builtin.method-signature", "{\"parameterTypes\":[]}")) }
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("builtin.method-signature", "{\"parameterTypes\":[]}", EntityKind.CLASS, mapOf("owner" to "logger"))) }
        val valid = rule("builtin.method-signature", "{\"parameterTypes\":[\"Ljava/lang/String;\"],\"returnSameAsOwner\":true}", requires = mapOf("owner" to "logger"))
        StrategyRegistry.validate(valid)
        assertEquals(mapOf("owner" to EntityKind.CLASS), StrategyRegistry.dependencyKinds(valid))
    }
    @Test fun `malformed descriptors indexes and flags are input errors`() {
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("builtin.method-signature", "{\"parameterTypes\":[\"String\"]}", requires = mapOf("owner" to "logger"))) }
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("messages.handler-name-method", "{\"logLiteral\":\"log\",\"argumentIndex\":999999999999}", requires = mapOf("lifecycle" to "root"))) }
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("builtin.method-signature", "{\"parameterTypes\":[],\"requiredFlags\":[\"MADE_UP\"]}", requires = mapOf("owner" to "logger"))) }
    }

    @Test fun `RPC related roles inherit all RPC configuration from a method dependency`() {
        listOf("descriptor", "builder", "marshaller").forEach { role ->
            val valid = rule("messages.rpc-related-type", "{\"role\":\"$role\"}", EntityKind.CLASS, mapOf("descriptor" to "rpc"))
            StrategyRegistry.validate(valid)
            assertEquals(mapOf("descriptor" to EntityKind.METHOD), StrategyRegistry.dependencyKinds(valid))
        }
        for (parameters in listOf("{}", "{\"role\":\"request\"}", "{\"role\":\"builder\",\"service\":\"replacement\"}",
            "{\"role\":\"marshaller\",\"requestLabel\":\"replacement\"}")) {
            assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("messages.rpc-related-type", parameters, EntityKind.CLASS, mapOf("descriptor" to "rpc"))) }
        }
        assertFailsWith<ValidationException> { StrategyRegistry.validate(rule("messages.rpc-related-type", "{\"role\":\"builder\"}", requires = mapOf("descriptor" to "rpc"))) }
    }

    @Test fun `RPC related type rejects a method anchor from another producer`() {
        val hash = "a".repeat(64)
        val owner = ClassRef(hash, "Lowner;", "classes.dex")
        val method = MethodRef(owner, "build", "()Ljava/lang/Object;")
        // A valid unique METHOD proof is not by itself an RPC descriptor proof.
        val other = rule("fixture.method-producer", "{}")
        val fact = MatchFact(owner, MatchStatus.PASS, listOf(FactorResult("fixture", MatchStatus.PASS, "unique method")), emptyMap(), method = method)
        val proof = RuleProofs.create(hash, other, "engine", listOf(fact))
        val anchor = SupportAnchor("rpc", EntityRef(owner, method), other, proof, emptyList())
        val consumer = rule("messages.rpc-related-type", "{\"role\":\"descriptor\"}", EntityKind.CLASS, mapOf("descriptor" to "rpc"))
        assertFailsWith<ValidationException> { StrategyRegistry.checkDependencies(consumer, Artifact("fixture.apk", hash), mapOf("rpc" to anchor)) }
    }

    @Test fun `unresolved RPC dependency producer is validated from definitions before waiting`() {
        val consumer = rule("messages.rpc-related-type", "{\"role\":\"builder\"}", EntityKind.CLASS, mapOf("descriptor" to "rpc"))
        val wrong = rule("builtin.method-signature", "{\"parameterTypes\":[]}", requires = mapOf("owner" to "root"))
        val failure = assertFailsWith<ValidationException> {
            StrategyRegistry.validateDependencyDefinitions(consumer, mapOf("rpc" to wrong))
        }
        assertTrue(failure.message!!.contains("produced by messages.rpc-descriptor"))
        val valid = rule("messages.rpc-descriptor", "{\"service\":\"fixture\",\"rpc\":\"Read\"}")
        StrategyRegistry.validateDependencyDefinitions(consumer, mapOf("rpc" to valid))
        assertFailsWith<ValidationException> { StrategyRegistry.validateDependencyDefinitions(consumer, emptyMap()) }
        assertFailsWith<ValidationException> {
            StrategyRegistry.validateDependencyDefinitions(consumer, mapOf("rpc" to rule("messages.named-handler", "{\"component\":\"Fixture\"}",
                EntityKind.CLASS, mapOf("nameMethod" to "root"))))
        }
    }
}
