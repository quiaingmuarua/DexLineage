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
}
