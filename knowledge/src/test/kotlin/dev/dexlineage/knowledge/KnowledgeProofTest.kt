package dev.dexlineage.knowledge

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class KnowledgeProofTest {
    @TempDir lateinit var directory: Path
    private val hash = "a".repeat(64)
    private val owner = ClassRef(hash, "La;", "classes.dex")
    private val rule = RuleProofs.revision(listOf(Locator("string-use", "component")))
    private fun proof() = RuleProofs.create(hash, rule, "test-build", listOf(MatchFact(owner, MatchStatus.PASS,
        listOf(FactorResult("anchor", MatchStatus.PASS, "Exact constant use")), mapOf("literal" to "component"))))
    private fun entry(root: Path): KnowledgeEntry {
        val id = "b".repeat(64)
        val java = "evidence/$id/code.java"
        Files.createDirectories(root.resolve("evidence/$id"))
        Files.writeString(root.resolve(java), "class a {}")
        val evidence = KnowledgeEvidence(id, owner, java, Digests.file(root.resolve(java)), null, null, false, emptyList())
        return KnowledgeEntry("component", "Component", owner, mapOf("literal" to "component"), rule.locators,
            listOf(evidence), "Owner responsibility verified", "review", rule, proof())
    }
    @Test fun `confirmed entries must carry the rule and same unique owner proof`() {
        val valid = entry(directory)
        fun knowledge(e: KnowledgeEntry) = VersionKnowledge(knowledgeId = "", artifact = Artifact("not-required-for-reading.apk", hash),
            entries = listOf(e), unresolved = emptyList(), provenance = "test")
        assertFailsWith<ValidationException> { KnowledgeFiles.write(directory, knowledge(valid.copy(resolution = null))) }
        assertFailsWith<ValidationException> { KnowledgeFiles.write(directory, knowledge(valid.copy(ruleRevision = null))) }
        assertFailsWith<ValidationException> { KnowledgeFiles.write(directory, knowledge(valid.copy(binding = owner.copy(descriptor = "Lb;")))) }
        val published = KnowledgeFiles.write(directory, knowledge(valid))
        assertEquals(published, KnowledgeFiles.read(directory.resolve("knowledge.json")))
    }
    @Test fun `pending legacy knowledge keeps history without claiming a current proof`() {
        val last = entry(directory).copy(ruleRevision = null, resolution = null)
        val value = VersionKnowledge(knowledgeId = "", artifact = Artifact("new.apk", "c".repeat(64)), entries = emptyList(),
            unresolved = listOf(UnresolvedKnowledge(last, "old-knowledge", "ambiguous", "old-run")), provenance = "import")
        val published = KnowledgeFiles.write(directory, value)
        assertEquals(last, KnowledgeFiles.read(directory.resolve("knowledge.json")).unresolved.single().entry)
        assertTrue(published.entries.isEmpty())
    }
    @Test fun `matching proof hashes reject changed result and rule`() {
        val p = proof()
        RuleProofs.validate(p)
        assertFailsWith<ValidationException> { RuleProofs.validate(p.copy(status = ResolutionStatus.NO_MATCH)) }
        assertFailsWith<ValidationException> { RuleProofs.validate(p.copy(rule = RuleProofs.revision(listOf(Locator("string-use", "other"))))) }
        assertFailsWith<ValidationException> { RuleProofs.validate(p.copy(matches = emptyList())) }
    }
}
