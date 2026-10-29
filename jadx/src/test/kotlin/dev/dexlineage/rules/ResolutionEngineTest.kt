package dev.dexlineage.rules

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.*

class ResolutionEngineTest {
    @TempDir lateinit var temp: Path
    private val apk = Artifact("not-opened-by-data-fixture.apk", "a".repeat(64))
    private fun rule(vararg literals: String) = RuleProofs.revision(literals.map { Locator("string-use", it) })
    private fun fact(owner: String, status: MatchStatus = MatchStatus.PASS, index: Int = 0): MatchFact =
        MatchFact(ClassRef(apk.sha256, owner, "classes.dex"), status,
            listOf(FactorResult("anchor", status, "Fixture query evidence")), emptyMap(), locatorIndex = index)
    private fun query(vararg facts: MatchFact, diagnostics: List<String> = emptyList()): QueryResult {
        val classes = facts.associate { it.owner.descriptor to it.owner.dexEntry }
        val scan = ScanResult(classes, emptyMap(), ScanStats(classes.size, 0, 0, 0, 0, diagnostics))
        return QueryResult(facts.toList(), scan, null)
    }

    @Test fun `alternative locators and fields for one class remain a unique identity`() {
        val revision = rule("first", "second")
        val result = ResolutionEngine.resolveQuery(apk, listOf(revision), "build", query(
            fact("Lone;"), fact("Lone;", MatchStatus.UNKNOWN, 0), fact("Lone;", index = 1),
        )).getValue(revision.revisionId)
        assertEquals(ResolutionStatus.UNIQUE, result.status)
        assertEquals("Lone;", result.uniqueRef!!.descriptor)
        assertEquals(3, result.candidates.single().matches.size)
        RuleProofs.validate(result)
    }

    @Test fun `two certain entities remain ambiguous with all candidates retained`() {
        val revision = rule("shared")
        val result = ResolutionEngine.resolveQuery(apk, listOf(revision), "build", query(fact("Lb;"), fact("La;")))
            .getValue(revision.revisionId)
        assertEquals(ResolutionStatus.AMBIGUOUS, result.status)
        assertNull(result.uniqueRef)
        assertEquals(listOf("La;", "Lb;"), result.candidates.map { it.ref.descriptor })
    }

    @Test fun `an unresolved other entity cannot be treated as an excluded candidate`() {
        val revision = rule("shared")
        for (facts in listOf(arrayOf(fact("La;", MatchStatus.UNKNOWN)), arrayOf(fact("La;"), fact("Lb;", MatchStatus.UNKNOWN)))) {
            val result = ResolutionEngine.resolveQuery(apk, listOf(revision), "build", query(*facts)).getValue(revision.revisionId)
            assertEquals(ResolutionStatus.UNKNOWN, result.status)
            assertNull(result.uniqueRef)
        }
    }

    @Test fun `a failed predicate eliminates that entity but no hits is not an execution error`() {
        val revision = rule("literal")
        val failed = ResolutionEngine.resolveQuery(apk, listOf(revision), "build", query(fact("La;", MatchStatus.FAIL))).getValue(revision.revisionId)
        assertEquals(ResolutionStatus.NO_MATCH, failed.status)
        assertEquals(1, failed.matches.size)
        val absent = ResolutionEngine.resolveQuery(apk, listOf(revision), "build", query()).getValue(revision.revisionId)
        assertEquals(ResolutionStatus.NO_MATCH, absent.status)
        assertTrue(absent.matches.isEmpty())
    }

    @Test fun `flattened indexes are local to each immutable rule revision`() {
        val first = rule("a", "b")
        val second = rule("c")
        val result = ResolutionEngine.resolveQuery(apk, listOf(first, second), "build", query(
            fact("Lfirst;", index = 0), fact("Lfirst;", index = 1), fact("Lsecond;", index = 2),
        ))
        assertEquals(listOf(0, 1), result.getValue(first.revisionId).matches.map { it.locatorIndex })
        assertEquals(listOf(0), result.getValue(second.revisionId).matches.map { it.locatorIndex })
        assertEquals("Lsecond;", result.getValue(second.revisionId).uniqueRef!!.descriptor)
    }

    @Test fun `replacing a broad rule can resolve ambiguity but OR appending cannot`() {
        val broadAndNarrow = rule("broad", "narrow")
        val union = ResolutionEngine.resolveQuery(apk, listOf(broadAndNarrow), "build", query(
            fact("La;", index = 0), fact("Lb;", index = 0), fact("La;", index = 1),
        )).getValue(broadAndNarrow.revisionId)
        assertEquals(ResolutionStatus.AMBIGUOUS, union.status)
        val replacement = rule("narrow")
        val resolved = ResolutionEngine.resolveQuery(apk, listOf(replacement), "build", query(fact("La;"))).getValue(replacement.revisionId)
        assertEquals(ResolutionStatus.UNIQUE, resolved.status)
        assertNotEquals(union.rule.revisionId, resolved.rule.revisionId)
        assertNotEquals(union.resolutionId, resolved.resolutionId)
    }

    @Test fun `identical revision requests share execution and changed content cannot reuse an ID`() {
        val first = rule("one")
        val second = rule("two")
        val normalized = ResolutionEngine.normalizedRules(listOf(first, second, first))
        assertEquals(2, normalized.size)
        assertEquals(normalized.sortedBy { it.revisionId }, normalized)
        assertFailsWith<ValidationException> { ResolutionEngine.normalizedRules(listOf(first.copy(locators = second.locators))) }
        assertFailsWith<ValidationException> { ResolutionEngine.normalizedRules(listOf(RuleProofs.revision(listOf(Locator("not-supported", "anchor"))))) }
    }

    @Test fun `incomplete scan cannot become a no-match resolution`() {
        assertFailsWith<ExecutionException> {
            ResolutionEngine.resolveQuery(apk, listOf(rule("missing")), "build", query(diagnostics = listOf("unreadable dex")))
        }
        assertFailsWith<ValidationException> {
            ResolutionEngine.resolveQuery(apk, listOf(rule("missing")), "build", query(fact("La;", index = 5)))
        }
    }

    @Test fun `structural raw locations remain scoped to the bound initializer`() {
        val owner = ClassRef(apk.sha256, "La;", "classes.dex")
        val binding = FieldBinding(owner, "log", "LLogger;", 0x19, "<clinit>()V", null, null)
        val init = StringUseSite("classes.dex", "La;", "<clinit>()V", 2, 120, "literal")
        val unrelatedMethod = init.copy(methodDescriptor = "handle()V", codeUnitOffset = 10)
        val unrelatedOwner = init.copy(classDescriptor = "Lb;")
        assertEquals(listOf(init), RuleEngine.initializerUses(binding, listOf(init, unrelatedMethod, unrelatedOwner)))
    }

    @Test fun `build identity depends on class content not location packaging or timestamps`() {
        val directory = temp.resolve("classes")
        val first = directory.resolve("dev/dexlineage/example/A.class")
        val second = directory.resolve("dev/dexlineage/example/B.class")
        Files.createDirectories(first.parent)
        Files.write(first, byteArrayOf(1, 2, 3))
        Files.write(second, byteArrayOf(4, 5, 6))
        val jar = temp.resolve("relocated/artifact.jar")
        Files.createDirectories(jar.parent)
        ZipOutputStream(Files.newOutputStream(jar)).use { zip ->
            for (path in listOf(second, first)) {
                zip.putNextEntry(ZipEntry(directory.relativize(path).toString().replace('\\', '/')).apply { time = 123456L })
                zip.write(Files.readAllBytes(path)); zip.closeEntry()
            }
            zip.putNextEntry(ZipEntry("META-INF/build-note.txt")); zip.write("irrelevant".toByteArray()); zip.closeEntry()
        }
        val before = ResolutionEngine.fingerprintArtifacts(mapOf("module" to directory))
        assertEquals(before, ResolutionEngine.fingerprintArtifacts(mapOf("module" to jar)))
        Files.setLastModifiedTime(first, FileTime.fromMillis(9999999))
        assertEquals(before, ResolutionEngine.fingerprintArtifacts(mapOf("module" to directory)))
        Files.write(first, byteArrayOf(1, 2, 7))
        assertNotEquals(before, ResolutionEngine.fingerprintArtifacts(mapOf("module" to directory)))
    }
}
