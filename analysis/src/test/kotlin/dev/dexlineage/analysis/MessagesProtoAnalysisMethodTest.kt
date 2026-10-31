package dev.dexlineage.analysis

import dev.dexlineage.analysis.messages.*
import dev.dexlineage.io.*
import dev.dexlineage.messages.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.test.*

class MessagesProtoAnalysisMethodTest {
    @TempDir lateinit var temp: Path
    private fun profile(targets: List<Map<String, Any>> = listOf(
        mapOf("key" to "one", "fieldNumber" to 1, "cardinality" to "singular", "corpusTargetId" to "manual-one"),
        mapOf("key" to "two", "fieldNumber" to 2, "cardinality" to "repeated", "proposedName" to "Identifier"))) =
        AnalysisProfile(id = "proto", strategy = StrategySpec("messages.proto-fields", requires = mapOf("parent" to "parent.message")),
            method = AnalysisMethodSpec("messages.proto-relations", JsonFiles.gson.toJsonTree(mapOf("targets" to targets)).asJsonObject))

    @Test fun `declared relation targets are drafted even when discovery has no child facts`() {
        val p = profile(); val method = AnalysisMethods.forProfile(p)
        method.validate(p)
        assertEquals(2, method.seedRounds)
        assertEquals(setOf("manual-one"), method.corpusTargetIds(p))
        val items = method.drafts(p, emptyList())
        assertEquals(listOf("one", "two"), items.map { it.key })
        assertTrue(items.all { it.discoveryKey == null && it.semanticId == null && it.locators.isEmpty() })
        assertEquals("manual-one", items.first().corpusTargetId)
        assertEquals("messages.proto-field-type", items.first().strategy!!.strategyId)
        assertEquals(1, items.first().strategy!!.parameters.get("fieldNumber").asInt)
        assertEquals("repeated", items.last().strategy!!.parameters.get("cardinality").asString)
        assertEquals(mapOf("parent" to "parent.message"), items.last().strategy!!.requires)
    }

    @Test fun `invalid selector and hidden expected owner do not enter method drafts`() {
        val bad = listOf(
            mapOf("key" to "one", "fieldNumber" to 0, "cardinality" to "singular"),
            mapOf("key" to "one", "fieldNumber" to "1", "cardinality" to "singular"),
            mapOf("key" to "one", "fieldNumber" to 1.5, "cardinality" to "singular"),
            mapOf("key" to "one", "fieldNumber" to 1, "cardinality" to "map"),
            mapOf("key" to "one", "fieldNumber" to 1, "cardinality" to "singular", "expectedOwner" to "Lchild;"))
        bad.forEach { row -> assertFailsWith<ValidationException> { MessagesProtoAnalysisMethod.validate(profile(listOf(row))) } }
        val repeated = mapOf("key" to "same", "fieldNumber" to 1, "cardinality" to "singular")
        assertFailsWith<ValidationException> { MessagesProtoAnalysisMethod.validate(profile(listOf(repeated, repeated))) }
    }

    @Test fun `typed catalogue keeps absent targets and distinguishes facts from a matching decision`() {
        val apk = Artifact("unused.apk", "fixture-apk")
        val parent = ClassRef(apk.sha256, "Lparent;", "classes.dex")
        val child = ClassRef(apk.sha256, "Lchild;", "classes.dex")
        val source = MethodRef(parent, "metadata", "()V")
        val raw = ProtoFieldCatalogue(apkSha256 = apk.sha256, parent = parent,
            metadata = listOf(ProtoMetadataSite(source, 12, "RESOLVED")),
            fields = listOf(ProtoFieldFact(1, "singular", "message", "renamed", "Lchild;", 9, child, source, 12)), unresolvedPaths = emptyList())
        val path = temp.resolve("raw.json"); JsonFiles.writeNew(path, raw)
        val refs = listOf(ScenarioArtifactRef(MessagesProtoArtifacts.KIND, path.toString(), Digests.file(path)))
        val discovery = AnalysisDiscovery(discoveryId = "unit-discovery", engineBuildId = "unit-build", apk = apk, profileSource = apk,
            profile = profile(), classInventory = mapOf(parent.descriptor to parent.dexEntry, child.descriptor to child.dexEntry),
            leads = emptyList(), matches = emptyList(), scan = ScanStats(2, 1, 1, 0, 0, emptyList()), matchCounts = emptyMap(),
            conditionCounts = emptyMap(), analysisDiagnostics = emptyList(), analysisMillis = 0, createdAt = "fixture", methodArtifacts = refs)
        val catalog = MessagesProtoAnalysisMethod.catalog(discovery)
        assertEquals(2, catalog.targets.size)
        assertEquals(listOf(child), catalog.targets.first().observedTypes)
        assertTrue(catalog.targets.last().observedTypes.isEmpty())
        assertTrue(catalog.targets.all { it.resolution == null && it.state == "NOT_EXECUTED" })
        assertEquals(2, catalog.counts.configuredTargets)
        assertEquals(1, catalog.counts.targetsWithObservedTypes)
        MessagesProtoAnalysisMethod.discoveryArtifacts(discovery, temp)
        MessagesProtoAnalysisMethod.validateDiscoveryArtifacts(discovery, temp)
    }
}
