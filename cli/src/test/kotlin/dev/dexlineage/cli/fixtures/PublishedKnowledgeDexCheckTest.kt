package dev.dexlineage.cli.fixtures

import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class PublishedKnowledgeDexCheckTest {
    private val hash = "a".repeat(64)
    private val owner = ClassRef(hash, "La;", "classes2.dex")
    private val integerOverload = RawDexMethod(RawDexMethodRef("La;", "b", listOf("I"), "Ljava/lang/String;"), 9, emptyList())
    private val stringOverload = RawDexMethod(RawDexMethodRef("La;", "b", listOf("Ljava/lang/String;"), "I"), 9, emptyList())
    private val clazz = RawDexClass("La;", "classes2.dex", listOf("fixture"), listOf(RawDexField("c", "I", 10)),
        listOf(integerOverload, stringOverload))
    private val index = RawDexIndex(hash, mapOf(clazz.descriptor to clazz))
    private fun entry(ref: ClassRef = owner) = KnowledgeEntry("semantic", "ReviewedName", ref, emptyMap(), emptyList(), emptyList(), "fixture", "fixture")
    private fun knowledge(ref: ClassRef = owner, anchorMethod: MethodRef? = null): VersionKnowledge {
        val anchors = anchorMethod?.let { method ->
            val rule = RuleRevision("rule", resultKind = EntityKind.METHOD)
            val resolution = Resolution(resolutionId = "proof", apkSha256 = hash, rule = rule, engineBuildId = "fixture",
                status = ResolutionStatus.UNIQUE, candidates = listOf(ResolutionCandidate(owner, MatchStatus.PASS, emptyList(), method)), matches = emptyList())
            listOf(SupportAnchor("factory", EntityRef(owner, method), rule, resolution))
        } ?: emptyList()
        return VersionKnowledge(knowledgeId = "publication", artifact = Artifact("recorded/path/unused.apk", hash),
            entries = listOf(entry(ref)), anchors = anchors, unresolved = emptyList(), provenance = "fixture")
    }

    @Test fun `published addresses select raw members by full identity without consuming historical bindings`() {
        val old = entry(ClassRef("old-apk", "Lmissing;", "classes.dex")).copy(semanticId = "unresolved")
        val knowledge = knowledge(anchorMethod = MethodRef(owner, "b", "(Ljava/lang/String;)I"))
            .copy(unresolved = listOf(UnresolvedKnowledge(old, "old-knowledge", "NO_MATCH", "old-run")))

        val facts = PublishedKnowledgeDexCheck.verify(index, knowledge)

        assertEquals("publication", facts.knowledgeId)
        assertEquals(clazz, facts.entries.single().clazz)
        assertEquals("ReviewedName", facts.entries.single().name)
        assertEquals(listOf(RawDexField("c", "I", 10)), facts.entries.single().clazz.fields)
        assertEquals(stringOverload, facts.anchors.single().method)
        assertEquals(listOf("unresolved"), facts.unresolvedSemanticIds)
    }

    @Test fun `wrong APK DEX entry and absent class cannot fall back to another address`() {
        val wrong = listOf(
            knowledge().copy(artifact = Artifact("unused", "other-apk")),
            knowledge(owner.copy(apkSha256 = "other-apk")),
            knowledge(owner.copy(dexEntry = "classes.dex")),
            knowledge(owner.copy(descriptor = "Lmissing;")))
        wrong.forEach { input -> assertFailsWith<IllegalArgumentException> { PublishedKnowledgeDexCheck.verify(index, input) } }
    }

    @Test fun `method lookup cannot accept another overload return type or owner`() {
        val wrong = listOf(
            MethodRef(owner, "other", "(I)Ljava/lang/String;"),
            MethodRef(owner, "b", "(J)Ljava/lang/String;"),
            MethodRef(owner, "b", "(I)I"),
            MethodRef(owner.copy(descriptor = "Lother;"), "b", "(I)Ljava/lang/String;"))
        wrong.forEach { method ->
            assertFailsWith<IllegalArgumentException> { PublishedKnowledgeDexCheck.verify(index, knowledge(anchorMethod = method)) }
        }
    }

    @Test fun `an existing but semantically wrong class must remain visible to the independent oracle`() {
        val other = RawDexClass("Lother;", "classes.dex", emptyList(), emptyList(), emptyList())
        val raw = index.copy(classes = index.classes + (other.descriptor to other))
        val wrongBinding = owner.copy(descriptor = other.descriptor, dexEntry = other.dexEntry)
        val facts = PublishedKnowledgeDexCheck.verify(raw, knowledge(wrongBinding))
        assertEquals(other, facts.entries.single().clazz)
        assertNotEquals(clazz.descriptor, facts.entries.single().clazz.descriptor)
        // The caller's source-authored oracle, rather than this address consumer, judges semantic correctness.
    }
}
