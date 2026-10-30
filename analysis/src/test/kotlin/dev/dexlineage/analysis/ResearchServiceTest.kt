package dev.dexlineage.analysis

import com.google.gson.JsonObject
import dev.dexlineage.apk.ResearchClassFacts
import dev.dexlineage.apk.ResearchFieldFact
import dev.dexlineage.io.ValidationException
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import kotlin.test.*

class ResearchServiceTest {
    private val apk = Artifact("source.apk", "a".repeat(64))
    private val owner = ClassRef(apk.sha256, "La;", "classes2.dex")
    private val target = ManualTarget("manual-a", owner, "ManualOwner", 0)
    private fun annotation(kind: String, member: String? = null, ref: ClassRef = owner) =
        ManualAnnotation(kind, ref.descriptor, member, "Annotated$kind",
            if (kind.startsWith("LOCAL_")) JsonObject().apply { addProperty("index", 7) } else null, JsonObject())
    private val annotations = listOf(annotation("CLASS"), annotation("FIELD", "b:I"),
        annotation("METHOD", "c()V"), annotation("LOCAL_VAR", "c()V"),
        annotation("CLASS", ref = owner.copy(descriptor = "Lother;")))
    private val corpus = ManualCorpus(corpusId = "corpus", apk = apk, project = Artifact("project.jadx", "project-hash"),
        projectVersion = 1, annotations = annotations, targets = listOf(target),
        annotationCounts = annotations.groupingBy { it.kind }.eachCount())
    private val facts = ResearchClassFacts(owner, 1, "Ljava/lang/Object;", emptyList(), listOf(ResearchFieldFact("b", "I", 2)), emptyList())
    private val evidence = EvidenceRecord(evidenceId = "evidence", runId = "research-namespace", ref = owner,
        javaPath = "evidence/code.java", javaSha256 = "java-hash", smaliPath = "evidence/code.smali", smaliSha256 = "smali-hash",
        incomplete = true, diagnostics = listOf("Method not decompiled"), elapsedMillis = 1)

    @Test fun `manual targets are selectable before rules and unknown duplicate or empty selection is rejected`() {
        assertEquals(listOf(target), ResearchService.selectTargets(corpus, listOf(target.targetId)))
        for (ids in listOf(emptyList(), listOf(""), listOf("missing"), listOf(target.targetId, target.targetId))) {
            assertFailsWith<ValidationException> { ResearchService.selectTargets(corpus, ids) }
        }
    }

    @Test fun `research retains member and local annotations with partial code and original identity`() {
        val result = ResearchService.attachTargets(corpus, listOf(target), listOf(facts), listOf(evidence)).single()
        assertEquals(listOf("CLASS", "FIELD", "METHOD", "LOCAL_VAR"), result.annotations.map { it.kind })
        assertEquals(7, result.annotations.last().codeRef!!.get("index").asInt)
        assertEquals(owner, result.facts.ref)
        assertEquals(listOf(ResearchFieldFact("b", "I", 2)), result.facts.fields)
        assertTrue(result.evidence.incomplete)
        assertEquals("evidence/code.smali", result.evidence.smaliPath)
        assertEquals(listOf("Method not decompiled"), result.evidence.diagnostics)
    }

    @Test fun `research cannot attach code or facts from another raw entity`() {
        for (foreign in listOf(owner.copy(apkSha256 = "foreign"), owner.copy(dexEntry = "classes.dex"), owner.copy(descriptor = "Lother;"))) {
            assertFailsWith<ValidationException> {
                ResearchService.attachTargets(corpus, listOf(target), listOf(facts.copy(ref = foreign)), listOf(evidence))
            }
            assertFailsWith<ValidationException> {
                ResearchService.attachTargets(corpus, listOf(target), listOf(facts), listOf(evidence.copy(ref = foreign)))
            }
        }
    }

    @Test fun `research namespace freezes corpus selection and implementation identity`() {
        val file = Artifact("corpus.json", "corpus-file-hash")
        val id = ResearchService.identity(file, corpus, listOf(target), "build-a")
        assertEquals(id, ResearchService.identity(file, corpus, listOf(target), "build-a"))
        assertNotEquals(id, ResearchService.identity(file, corpus, listOf(target), "build-b"))
        assertNotEquals(id, ResearchService.identity(file.copy(sha256 = "changed"), corpus, listOf(target), "build-a"))
    }
}
