package dev.dexlineage.cli.fixtures

import com.google.gson.JsonObject
import dev.dexlineage.model.VersionKnowledge
import java.nio.file.Path
import kotlin.test.*

/** Test truth stays outside the knowledge consumer and never becomes matcher input. */
internal data class ExpectedPublishedAnchor(val sourceClass: String, val methodName: String? = null,
    val methodDescriptor: String? = null)
internal data class ExpectedPublishedField(val name: String, val type: String, val flags: Int? = null)
internal data class ExpectedPublishedMethod(val name: String, val descriptor: String, val flags: Int? = null)
internal data class ExpectedPublishedMembers(val fields: List<ExpectedPublishedField> = emptyList(),
    val methods: List<ExpectedPublishedMethod> = emptyList())

internal object PublishedFixtureAssertions {
    fun verify(cli: FixtureCli, apk: Path, knowledgeFile: Path, oracle: R8Oracle,
               entriesByName: Map<String, String>, anchorsByKey: Map<String, ExpectedPublishedAnchor> = emptyMap(),
               membersByName: Map<String, ExpectedPublishedMembers> = emptyMap()): PublishedDexFacts {
        val reportPath = "dex-consumption/${knowledgeFile.parent.fileName}.json"
        try {
            // Re-open the published file. A prepared Run/Resolution is not the consumer's input.
            val facts = PublishedKnowledgeDexCheck.verify(apk, knowledgeFile)
            val knowledge = cli.read<VersionKnowledge>(knowledgeFile)
            assertEquals(knowledge.knowledgeId, facts.knowledgeId)
            assertEquals(knowledge.entries.map { it.semanticId }.toSet(), facts.entries.map { it.semanticId }.toSet())
            assertEquals(knowledge.anchors.map { it.key }.toSet(), facts.anchors.map { it.key }.toSet())
            assertEquals(knowledge.unresolved.map { it.entry.semanticId }.toSet(), facts.unresolvedSemanticIds.toSet())
            assertTrue(facts.entries.none { it.semanticId in facts.unresolvedSemanticIds }, "Historical unresolved bindings must not be consumed")
            assertOracle(facts, oracle, entriesByName, anchorsByKey)
            val memberChecks = facts.entries.flatMap { fact ->
                val sourceClass = entriesByName.getValue(fact.name)
                val declared = membersByName[fact.name] ?: ExpectedPublishedMembers()
                declared.fields.map { expected ->
                    val identity = oracle.field(sourceClass, expected.name, expected.type)
                    val field = assertNotNull(fact.clazz.fields.singleOrNull { it.name == identity.name && it.type == identity.type },
                        "Published ${fact.name} lacks independently mapped field $identity")
                    expected.flags?.let { assertEquals(it, field.flags, "Field access flags $identity") }
                    mapOf("semanticId" to fact.semanticId, "kind" to "FIELD", "sourceOwner" to sourceClass,
                        "sourceName" to expected.name, "sourceType" to expected.type, "actual" to identity, "flags" to field.flags)
                } + declared.methods.map { expected ->
                    val identity = oracle.method(sourceClass, expected.name, expected.descriptor)
                    val method = assertNotNull(fact.clazz.methods.singleOrNull { it.ref == identity },
                        "Published ${fact.name} lacks independently mapped full method $identity")
                    expected.flags?.let { assertEquals(it, method.flags, "Method access flags $identity") }
                    mapOf("semanticId" to fact.semanticId, "kind" to "METHOD", "sourceOwner" to sourceClass,
                        "sourceName" to expected.name, "sourceDescriptor" to expected.descriptor, "actual" to identity, "flags" to method.flags)
                }
            }
            val entries = facts.entries.map { fact ->
                val entry = knowledge.entries.single { it.semanticId == fact.semanticId }
                val rule = assertNotNull(entry.ruleRevision)
                val proof = assertNotNull(entry.resolution)
                assertEquals(rule, proof.rule)
                assertEquals(facts.apkSha256, proof.apkSha256)
                assertEquals(fact.clazz.descriptor, entry.binding.descriptor)
                mapOf("semanticId" to fact.semanticId, "name" to fact.name, "descriptor" to fact.clazz.descriptor,
                    "dexEntry" to fact.clazz.dexEntry, "ruleRevisionId" to rule.revisionId,
                    "resolutionId" to proof.resolutionId, "proofApkSha256" to proof.apkSha256,
                    "sourceClass" to entriesByName.getValue(fact.name), "r8OracleAsserted" to true)
            }
            cli.write(reportPath, mapOf(
                "schemaVersion" to 1, "knowledgeFile" to knowledgeFile.toString(), "knowledgeId" to facts.knowledgeId,
                "apkSha256" to facts.apkSha256, "elapsedMillis" to facts.elapsedMillis,
                "consumedCurrentClasses" to facts.entries.size, "consumedAnchors" to facts.anchors.size,
                "consumedAnchorMethods" to facts.anchors.count { it.method != null },
                "distinctConsumedClasses" to (facts.entries.map { it.clazz.descriptor } + facts.anchors.map { it.clazz.descriptor }).distinct().size,
                "unresolvedNotConsumed" to facts.unresolvedSemanticIds, "entries" to entries,
                "verifiedMemberCount" to memberChecks.size, "memberChecks" to memberChecks,
                "anchors" to facts.anchors.map { mapOf("key" to it.key, "descriptor" to it.clazz.descriptor,
                    "dexEntry" to it.clazz.dexEntry, "method" to it.method?.ref, "r8OracleAsserted" to true) },
                "status" to "PASS"))
            return facts
        } catch (failure: Throwable) {
            cli.write(reportPath, mapOf("schemaVersion" to 1, "status" to "FAIL", "knowledgeFile" to knowledgeFile.toString(),
                "apk" to apk.toString(), "errorType" to failure.javaClass.name, "error" to (failure.message ?: "No diagnostic message")))
            throw failure
        }
    }

    fun assertOracle(facts: PublishedDexFacts, oracle: R8Oracle, entriesByName: Map<String, String>,
                     anchorsByKey: Map<String, ExpectedPublishedAnchor>) {
        facts.entries.forEach { entry ->
            val expected = assertNotNull(entriesByName[entry.name], "Unexpected published semantic name ${entry.name}")
            assertEquals(oracle.descriptor(expected), entry.clazz.descriptor, "Published ${entry.name} must resolve to the independent source identity")
        }
        facts.anchors.forEach { anchor ->
            val expected = assertNotNull(anchorsByKey[anchor.key], "Unexpected published anchor ${anchor.key}")
            assertEquals(oracle.descriptor(expected.sourceClass), anchor.clazz.descriptor, "Anchor ${anchor.key} owner")
            if (expected.methodName == null) assertNull(anchor.method, "CLASS anchor ${anchor.key}")
            else assertEquals(oracle.method(expected.sourceClass, expected.methodName, expected.methodDescriptor!!),
                assertNotNull(anchor.method).ref, "Anchor ${anchor.key} full owner/name/parameters/return identity")
        }
    }

    /** Invalid bindings are test copies, never imported into a production run or candidate set. */
    fun negativeCopies(cli: FixtureCli, apk: Path, knowledgeFile: Path, oracle: R8Oracle,
                       entriesByName: Map<String, String>, anchorsByKey: Map<String, ExpectedPublishedAnchor>,
                       otherExistingSourceClass: String) {
        val original = cli.read<JsonObject>(knowledgeFile)
        val checks = mutableListOf<Map<String, Any>>()
        fun copy(label: String, change: (JsonObject) -> Unit): Path =
            cli.write("dex-negative/$label/knowledge.json", original.deepCopy().also(change))
        fun rejected(label: String, change: (JsonObject) -> Unit) {
            val path = copy(label, change)
            val failure = assertFailsWith<IllegalArgumentException>(label) { PublishedKnowledgeDexCheck.verify(apk, path) }
            checks += mapOf("case" to label, "rejectedBy" to "raw-dex-consumer", "reason" to (failure.message ?: failure.javaClass.name))
        }
        fun binding(value: JsonObject) = value.getAsJsonArray("entries")[0].asJsonObject.getAsJsonObject("binding")
        rejected("wrong-apk-sha") { it.getAsJsonObject("artifact").addProperty("sha256", "0".repeat(64)) }
        rejected("wrong-binding-apk-sha") { binding(it).addProperty("apkSha256", "0".repeat(64)) }
        rejected("wrong-dex-entry") { binding(it).addProperty("dexEntry", "classes999999.dex") }
        rejected("missing-class") { binding(it).addProperty("descriptor", "Lfixture/MissingPublishedClass;") }
        if (original.getAsJsonArray("anchors").any { it.asJsonObject.getAsJsonObject("binding").get("method")?.isJsonObject == true }) {
            fun method(value: JsonObject) = value.getAsJsonArray("anchors").first {
                it.asJsonObject.getAsJsonObject("binding").get("method")?.isJsonObject == true
            }.asJsonObject.getAsJsonObject("binding").getAsJsonObject("method")
            rejected("wrong-method-return") {
                val m = method(it); m.addProperty("descriptor", m["descriptor"].asString.substringBefore(')') + ")J")
            }
            rejected("wrong-method-parameters") {
                val m = method(it); m.addProperty("descriptor", "(J" + m["descriptor"].asString.drop(1))
            }
        }
        val raw = RawDex.read(apk)
        val replacement = raw.classes.getValue(oracle.descriptor(otherExistingSourceClass))
        val wrongExisting = copy("other-existing-class") { value ->
            val target = binding(value)
            assertNotEquals(target["descriptor"].asString, replacement.descriptor)
            target.addProperty("descriptor", replacement.descriptor)
            target.addProperty("dexEntry", replacement.dexEntry)
        }
        // The physical class really exists. Only the independent semantic oracle can reject it.
        val physicallyValid = PublishedKnowledgeDexCheck.verify(apk, wrongExisting)
        assertTrue(physicallyValid.entries.any { it.clazz.descriptor == replacement.descriptor })
        assertFailsWith<AssertionError> { assertOracle(physicallyValid, oracle, entriesByName, anchorsByKey) }
        checks += mapOf("case" to "other-existing-class", "rawDexAccepted" to true, "rejectedBy" to "independent-r8-oracle")
        cli.write("dex-negative/summary.json", mapOf("schemaVersion" to 1, "checks" to checks, "status" to "PASS"))
    }
}
