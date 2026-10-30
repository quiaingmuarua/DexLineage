package dev.dexlineage.knowledge

import com.google.gson.JsonObject
import dev.dexlineage.io.ValidationException
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class AnchorProofTest {
    private val owner = ClassRef("a".repeat(64), "Llogger;", "classes.dex")
    private val strategy = StrategySpec("builtin.method-signature", resultKind = EntityKind.METHOD)
    private fun fact(name: String, status: MatchStatus = MatchStatus.PASS) = MatchFact(owner, status,
        listOf(FactorResult("signature", status, "Observed original method signature")), emptyMap(),
        method = MethodRef(owner, name, "(Ljava/lang/String;Ljava/lang/String;)Llogger;"))

    @Test fun `two matching methods in one owner remain ambiguous`() {
        val rule = RuleProofs.revision(emptyList(), strategy)
        val result = RuleProofs.create(owner.apkSha256, rule, "engine", listOf(fact("a"), fact("b")))
        assertEquals(ResolutionStatus.AMBIGUOUS, result.status)
        assertEquals(2, result.candidates.size)
        RuleProofs.validate(result)
    }

    @Test fun `repeated sites for same method merge but unknown competitor blocks`() {
        val rule = RuleProofs.revision(emptyList(), strategy)
        val unique = RuleProofs.create(owner.apkSha256, rule, "engine", listOf(fact("a"), fact("a")))
        assertEquals(ResolutionStatus.UNIQUE, unique.status)
        assertNull(unique.uniqueRef)
        assertEquals("a", unique.uniqueMethod!!.name)
        val blocked = RuleProofs.create(owner.apkSha256, rule, "engine", listOf(fact("a"), fact("b", MatchStatus.UNKNOWN)))
        assertEquals(ResolutionStatus.UNKNOWN, blocked.status)
    }

    @Test fun `dependency identity binds downstream proof and another APK is rejected`() {
        val upstream = RuleProofs.revision(listOf(Locator("string-use", "logger marker")))
        val upstreamProof = RuleProofs.create(owner.apkSha256, upstream, "engine", listOf(
            MatchFact(owner, MatchStatus.PASS, listOf(FactorResult("anchor", MatchStatus.PASS, "marker")), emptyMap())))
        val anchor = SupportAnchor("logger", EntityRef(owner), upstream, upstreamProof)
        val rule = RuleProofs.revision(emptyList(), strategy.copy(requires = mapOf("owner" to "logger")))
        val result = RuleProofs.create(owner.apkSha256, rule, "engine", listOf(fact("a")), mapOf("owner" to anchor))
        RuleProofs.validate(result)
        assertFailsWith<ValidationException> { RuleProofs.validate(result.copy(dependencies = emptyMap())) }
        assertFailsWith<ValidationException> {
            RuleProofs.create("b".repeat(64), rule, "engine", emptyList(), mapOf("owner" to anchor))
        }
        assertFailsWith<ValidationException> {
            RuleProofs.validateDependencies(mapOf("logger" to rule), listOf(rule), emptyList())
        }
    }

    @Test fun `parameter key order does not change rule identity but changed values do`() {
        val a = JsonObject().apply { addProperty("one", 1); addProperty("two", 2) }
        val b = JsonObject().apply { addProperty("two", 2); addProperty("one", 1) }
        assertEquals(RuleProofs.revision(emptyList(), strategy.copy(parameters = a)), RuleProofs.revision(emptyList(), strategy.copy(parameters = b)))
        b.addProperty("one", 3)
        assertNotEquals(RuleProofs.revision(emptyList(), strategy.copy(parameters = a)), RuleProofs.revision(emptyList(), strategy.copy(parameters = b)))
    }
}
