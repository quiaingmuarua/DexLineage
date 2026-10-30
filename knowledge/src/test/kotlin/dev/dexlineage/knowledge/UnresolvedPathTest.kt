package dev.dexlineage.knowledge

import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class UnresolvedPathTest {
    private val hash = "a".repeat(64)
    private val owner = ClassRef(hash, "Lproto;", "classes.dex")
    private val source = MethodRef(ClassRef(hash, "Lcaller;", "classes.dex"), "read", "()Ljava/lang/Object;")
    private val rule = RuleProofs.revision(listOf(Locator("string-use", "literal")))
    private val fact = MatchFact(owner, MatchStatus.PASS, listOf(FactorResult("shape", MatchStatus.PASS, "complete")), emptyMap())
    private val path = UnresolvedPath(source, 17, "Unresolved construction", "fixture.Service", "Read")

    @Test fun `unbound path blocks unique and cannot masquerade as no match`() {
        for (facts in listOf(emptyList(), listOf(fact))) {
            val proof = RuleProofs.create(hash, rule, "engine", facts, unresolvedPaths = listOf(path))
            assertEquals(ResolutionStatus.UNKNOWN, proof.status)
            assertNull(proof.uniqueEntity)
            assertEquals(facts.size, proof.candidates.size, "No invented entity candidate")
            RuleProofs.validate(proof)
            assertFailsWith<ValidationException> { RuleProofs.validate(proof.copy(unresolvedPaths = null)) }
        }
    }

    @Test fun `definite ambiguity remains ambiguous even with an unresolved path`() {
        val second = fact.copy(owner = owner.copy(descriptor = "Lother;"))
        val proof = RuleProofs.create(hash, rule, "engine", listOf(fact, second), unresolvedPaths = listOf(path))
        assertEquals(ResolutionStatus.AMBIGUOUS, proof.status)
        RuleProofs.validate(proof)
    }

    @Test fun `path identity and content participate in proof validation`() {
        assertFailsWith<ValidationException> {
            RuleProofs.create(hash, rule, "engine", listOf(fact), unresolvedPaths = listOf(path.copy(source = source.copy(owner = source.owner.copy(apkSha256 = "b".repeat(64))))))
        }
        assertFailsWith<ValidationException> { RuleProofs.create(hash, rule, "engine", emptyList(), unresolvedPaths = listOf(path.copy(codeUnitOffset = -1))) }
        val a = RuleProofs.create(hash, rule, "engine", listOf(fact), unresolvedPaths = listOf(path))
        val b = RuleProofs.create(hash, rule, "engine", listOf(fact), unresolvedPaths = listOf(path.copy(rpc = "Write")))
        assertNotEquals(a.resolutionId, b.resolutionId)
    }

    @Test fun `old proof JSON and digest omit the additive null field`() {
        val proof = RuleProofs.create(hash, rule, "engine", listOf(fact))
        assertFalse(JsonFiles.encode(proof).contains("unresolvedPaths"))
        val old = JsonParser.parseString(JsonFiles.encode(proof)).asJsonObject
        assertFalse(old.has("unresolvedPaths"))
        val reread = JsonFiles.gson.fromJson(old, Resolution::class.java)
        RuleProofs.validate(reread)
        assertEquals(proof, reread)
        assertEquals(proof, RuleProofs.create(hash, rule, "engine", listOf(fact), unresolvedPaths = emptyList()))
    }
}
