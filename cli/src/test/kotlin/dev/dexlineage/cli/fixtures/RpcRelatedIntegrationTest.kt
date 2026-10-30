package dev.dexlineage.cli.fixtures

import com.google.gson.JsonObject
import dev.dexlineage.analysis.*
import dev.dexlineage.migration.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import kotlin.test.*

/** Source-authored truth, real R8 APKs and installed CLI processes; no injected matching results. */
@Tag("fixture-integration")
class RpcRelatedIntegrationTest {
    private val namespace = "dev.dexlineage.fixture.related."
    private val roleTypes = linkedMapOf("descriptor" to "RelatedDescriptor", "builder" to "RelatedBuilder", "marshaller" to "WireContract")
    private val roleNames = mapOf("descriptor" to "FixtureRpcDescriptor", "builder" to "FixtureRpcBuilder", "marshaller" to "FixtureMarshallerContract")
    private lateinit var cli: FixtureCli
    private lateinit var root: Path
    private lateinit var manifest: FixtureManifest
    private lateinit var oracle: Map<String, R8Oracle>
    private fun apk(version: String) = root.resolve(manifest.versions.getValue(version).apk)
    private fun sourceType(name: String) = "L${(namespace + name).replace('.', '/')};"
    private fun rawType(version: String, name: String) = oracle.getValue(version).descriptor(namespace + name)
    private fun params(vararg pairs: Pair<String, Any>) = cli.gson.toJsonTree(pairs.toMap()).asJsonObject
    private fun rpc(service: String) = StrategySpec("messages.rpc-descriptor", params("service" to service, "rpc" to "GetGroupInfo"), EntityKind.METHOD)
    private fun related(role: String, key: String = "rpc") = StrategySpec("messages.rpc-related-type", params("role" to role), requires = mapOf("descriptor" to key))

    private fun setup(label: String) {
        root = Path.of(System.getProperty("dexlineage.fixtureRoot")).toAbsolutePath().parent.parent
        manifest = FixtureManifest.read(Path.of(System.getProperty("dexlineage.fixtureCases")))
        oracle = manifest.versions.mapValues { (_, v) -> R8Oracle(root.resolve(v.mapping)) }
        cli = FixtureCli(Path.of(System.getProperty("dexlineage.distributionDir")),
            Path.of(System.getProperty("dexlineage.fixtureResults")).resolve("rpc-related-$label-${UUID.randomUUID()}"), root)
        verifyFixtureShape()
    }

    private fun verifyFixtureShape() {
        val checks = listOf("v1", "v2").map { version ->
            val raw = RawDex.read(apk(version))
            val owner = raw.classes.getValue(rawType(version, "RelatedRpcCases"))
            assertNotEquals(sourceType("RelatedRpcCases"), owner.descriptor)
            val result = if (version == "v1") sourceType("RelatedDescriptor") else "Ljava/lang/Object;"
            val main = oracle.getValue(version).method(namespace + "RelatedRpcCases", "getGroupInfo", "()$result")
            assertNotEquals("getGroupInfo", main.name)
            assertNotNull(owner.methods.singleOrNull { it.ref == main })
            mapOf("version" to version, "apkSha256" to raw.apkSha256, "rpcMethod" to main,
                "prefixDecoys" to listOf("servicePrefixDecoy", "rpcPrefixDecoy").map { name ->
                    val expected = oracle.getValue(version).method(namespace + "RelatedRpcCases", name, "()Ljava/lang/Object;")
                    val method = owner.methods.single { it.ref == expected }
                    val literals = method.instructions.mapNotNull { it.literal }.toSet()
                    val pair = if (name == "servicePrefixDecoy") setOf("fixture.related.GroupExtra", "GetGroupInfo")
                        else setOf("fixture.related.Group", "GetGroupInfoExtended")
                    assertTrue(literals.containsAll(pair), "The prefix competitor must actually survive R8")
                    mapOf("method" to expected, "literals" to pair)
                })
        }
        roleTypes.values.forEach { assertNotEquals(rawType("v1", it), rawType("v2", it)) }
        cli.write("fixture-shape.json", mapOf("schemaVersion" to 1, "checks" to checks, "status" to "PASS"))
    }

    @Test fun `research precedes rules and related type knowledge migrates from a concrete to Object RPC return`() {
        setup("flow")
        val corpusPath = importCorpus()
        val corpus = cli.read<ManualCorpus>(corpusPath)
        val descriptorTarget = corpus.targets.single { it.manualName == roleNames.getValue("descriptor") }
        val research = researchUnconfigured(corpusPath, corpus)
        val items = roleTypes.keys.map { role -> AnalysisRuleItem(role, proposedName = roleNames.getValue(role), strategy = related(role),
            corpusTargetId = descriptorTarget.targetId.takeIf { role == "descriptor" }) }
        val rules = cli.write("inputs/related.json", AnalysisRuleFile(items = items,
            anchors = listOf(AnalysisAnchorDefinition("rpc", strategy = rpc("fixture.related.Group")))))
        var sourceBase: Path? = null
        for (round in 1..2) {
            val dir = cli.output.resolve("source-run-$round")
            val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk("v1"), "--rules", rules, "--corpus", corpusPath, "--run", dir)
            sourceBase?.let { args.addAll(listOf("--base-knowledge", it.resolve("knowledge.json"))) }
            cli.execute("source-$round-prepare", *args.toTypedArray())
            val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
            assertRpc(run.anchorTasks.single().resolution!!, "v1", "getGroupInfo", "()${sourceType("RelatedDescriptor")}")
            if (round == 1) {
                assertTrue(run.tasks.all { it.resolution == null && it.executionState == AnalysisExecutionState.WAITING_DEPENDENCY })
            } else {
                val reviews = run.tasks.map { task ->
                    assertRole(task.resolution!!, "v1", task.taskId)
                    val evidence = inspect("analysis", dir, task.taskId)
                    AnalysisReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT,
                        roleNames.getValue(task.taskId), Confidence.HIGH,
                        "Self-authored fixture defines this ${task.taskId} role in one RPC construction, independently checked with R8 source identity.",
                        listOf("Static protocol regression; this fixture review does not evaluate Agent semantic judgment or runtime RPC behavior."),
                        evidence.map { it.evidenceId })
                }
                val descriptor = run.tasks.single { it.taskId == "descriptor" }
                val researchEvidence = research.targets.single { it.target.targetId == descriptorTarget.targetId }.evidence
                assertEquals(descriptor.resolution!!.uniqueRef, researchEvidence.ref, "Same entity; only the research evidence namespace differs")
                assertNotEquals(run.runId, researchEvidence.runId)
                val invalid = reviews.single { it.taskId == "descriptor" }.copy(evidenceIds = listOf(researchEvidence.evidenceId))
                val invalidFile = cli.write("reviews/research-is-not-review-evidence.json", AnalysisReviewBatch(runId = run.runId,
                    apkSha256 = run.apk.sha256, items = listOf(invalid)))
                cli.execute("research-evidence-rejected", "analysis", "submit", "--run", dir, "--review", invalidFile, expectedExit = 2)
                val reviewFile = cli.write("reviews/source.json", AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256, items = reviews))
                cli.execute("source-submit", "analysis", "submit", "--run", dir, "--review", reviewFile)
            }
            val out = cli.output.resolve("source-published-$round")
            cli.execute("source-$round-publish", "analysis", "publish", "--run", dir, "--out", out)
            verifyPublished(out, "v1", round == 2)
            sourceBase = out
        }
        val sourceOut = sourceBase!!
        val source = cli.read<VersionKnowledge>(sourceOut.resolve("knowledge.json"))
        val ledger = cli.result<CorpusTargetPage>("unconfigured-stays-visible", "analysis", "targets", "--corpus", corpusPath,
            "--run", cli.output.resolve("source-run-2"), "--state", "ALL", "--limit", 20)
        assertEquals("UNCONFIGURED", ledger.items.single { it.target.manualName == "ResearchOnlyTarget" }.state)
        var targetBase: Path? = null
        for (round in 1..2) {
            val dir = cli.output.resolve("target-run-$round")
            val args = mutableListOf<Any>("migration", "prepare", "--knowledge", sourceOut.resolve("knowledge.json"),
                "--source-apk", apk("v1"), "--target-apk", apk("v2"), "--run", dir)
            targetBase?.let { args.addAll(listOf("--target-base", it.resolve("knowledge.json"))) }
            cli.execute("target-$round-prepare", *args.toTypedArray())
            val run = cli.read<MigrationRun>(dir.resolve("run.json"))
            assertRpc(run.anchorTasks.single().resolution!!, "v2", "getGroupInfo", "()Ljava/lang/Object;")
            assertEquals(source.anchors.single().rule, run.anchorTasks.single().rule)
            assertNotEquals(source.anchors.single().resolution.resolutionId, run.anchorTasks.single().resolution!!.resolutionId)
            assertEquals(source.entries.map { it.semanticId }.toSet(), run.tasks.map { it.taskId }.toSet())
            if (round == 1) assertTrue(run.tasks.all { it.resolution == null && it.executionState == MigrationExecutionState.WAITING_DEPENDENCY })
            else {
                val reviews = run.tasks.map { task ->
                    val role = roleNames.entries.single { it.value == task.entry.name }.key
                    assertRole(task.resolution!!, "v2", role)
                    assertEquals(task.entry.ruleRevision, task.rule, "The same knowledge rule is reused, with no manually rebuilt target locator")
                    assertNotEquals(task.entry.resolution!!.resolutionId, task.resolution!!.resolutionId)
                    val evidence = inspect("migration", dir, task.taskId)
                    MigrationReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT,
                        Confidence.HIGH, true, "Fixture-authored $role responsibility survives the v2 return-type and constructor layout changes.",
                        listOf("RPC declaration returns Object in v2; constructor role order and marshaller creation change, while the related semantic type remains fixed by source truth."),
                        listOf("Static fixture truth, not an Agent quality or runtime compatibility measurement."), evidence.map { it.evidenceId })
                }
                val file = cli.write("reviews/target.json", MigrationReviewBatch(runId = run.runId, sourceKnowledgeId = source.knowledgeId,
                    sourceApkSha256 = run.sourceApk.sha256, targetApkSha256 = run.targetApk.sha256, items = reviews))
                cli.execute("target-submit", "migration", "submit", "--run", dir, "--review", file)
            }
            val out = cli.output.resolve("target-published-$round")
            cli.execute("target-$round-publish", "migration", "publish", "--run", dir, "--out", out)
            verifyPublished(out, "v2", round == 2)
            targetBase = out
        }
        val target = cli.read<VersionKnowledge>(targetBase!!.resolve("knowledge.json"))
        assertEquals(source.entries.map { it.semanticId }.toSet(), target.entries.map { it.semanticId }.toSet())
        assertTrue(target.unresolved.isEmpty())
        val replay = cli.output.resolve("target-replay")
        cli.execute("target-replay", "migration", "publish", "--run", cli.output.resolve("target-run-2"), "--out", replay,
            "--at", targetBase.resolve("report.json"))
        assertEquals(Files.readString(targetBase.resolve("knowledge.json")), Files.readString(replay.resolve("knowledge.json")))
        verifyPublished(replay, "v2", true)
        cli.write("summary.json", mapOf("schemaVersion" to 1, "sourceNames" to source.entries.map { it.name },
            "targetNames" to target.entries.map { it.name }, "researchId" to research.researchId, "roundsPerVersion" to 2,
            "commands" to cli.commandCount, "timings" to cli.timingSummary, "status" to "PASS"))
    }

    @Test fun `related roles preserve unknown alternatives ambiguity and dependency provenance`() {
        setup("negative")
        val cases = linkedMapOf("partial" to "fixture.related.Partial", "multiple" to "fixture.related.Multiple", "duplicate" to "fixture.related.Duplicate")
        val definitions = AnalysisRuleFile(items = cases.keys.flatMap { key -> roleTypes.keys.map { role ->
            AnalysisRuleItem("$key-$role", proposedName = "Unpublished_${key}_$role", strategy = related(role, key))
        } }, anchors = cases.map { (key, service) -> AnalysisAnchorDefinition(key, strategy = rpc(service)) })
        val rules = cli.write("inputs/negative.json", definitions)
        for (version in listOf("v1", "v2")) {
            var base: Path? = null
            for (round in 1..2) {
                val dir = cli.output.resolve("$version-negative-run-$round")
                val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk(version), "--rules", rules, "--run", dir)
                base?.let { args.addAll(listOf("--base-knowledge", it.resolve("knowledge.json"))) }
                cli.execute("$version-negative-$round", *args.toTypedArray())
                val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
                val methodNames = mapOf("partial" to "partlyUnsupported", "multiple" to "multipleTypes", "duplicate" to "repeatedTypes")
                run.anchorTasks.forEach { assertRpc(it.resolution!!, version, methodNames.getValue(it.key), "()Ljava/lang/Object;") }
                assertTrue(run.anchorTasks.single { it.key == "partial" }.resolution!!.matches.any { it.status == MatchStatus.UNKNOWN },
                    "The upstream METHOD remains unique even when another construction in that same method is unknown")
                if (round == 1) assertTrue(run.tasks.all { it.resolution == null }) else {
                    roleTypes.forEach { (role, type) ->
                        val partial = run.tasks.single { it.taskId == "partial-$role" }.resolution!!
                        assertEquals(ResolutionStatus.UNKNOWN, partial.status)
                        assertTrue(partial.matches.none { it.status == MatchStatus.PASS }, "A complete branch must not hide an unsupported construction")
                        val multiple = run.tasks.single { it.taskId == "multiple-$role" }.resolution!!
                        assertEquals(ResolutionStatus.AMBIGUOUS, multiple.status)
                        val other = mapOf("descriptor" to "OtherDescriptor", "builder" to "OtherBuilder", "marshaller" to "OtherWireContract").getValue(role)
                        assertEquals(setOf(rawType(version, type), rawType(version, other)), multiple.candidates.map { it.ref.descriptor }.toSet())
                        assertRole(run.tasks.single { it.taskId == "duplicate-$role" }.resolution!!, version, role)
                    }
                    val invalidTask = run.tasks.single { it.taskId == "partial-descriptor" }
                    val invalidReview = cli.write("reviews/$version-invalid.json", AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256,
                        items = listOf(AnalysisReview(invalidTask.taskId, invalidTask.resolution!!.resolutionId, invalidTask.rule.revisionId,
                            ReviewAction.ACCEPT, "MustNotPublish", Confidence.HIGH, "Deliberate attempt to override unknown construction."))))
                    cli.execute("$version-unknown-review-rejected", "analysis", "submit", "--run", dir, "--review", invalidReview, expectedExit = 2)
                }
                val out = cli.output.resolve("$version-negative-published-$round")
                cli.execute("$version-negative-publish-$round", "analysis", "publish", "--run", dir, "--out", out)
                val anchorTruth = methodNames.mapValues { (_, name) -> ExpectedPublishedAnchor(namespace + "RelatedRpcCases", name, "()Ljava/lang/Object;") }
                val facts = PublishedFixtureAssertions.verify(cli, apk(version), out.resolve("knowledge.json"), oracle.getValue(version), emptyMap(), anchorTruth)
                assertTrue(facts.entries.isEmpty(), "Even duplicate same-type UNIQUE targets require semantic Review")
                assertEquals(cases.keys, facts.anchors.map { it.key }.toSet())
                assertEquals(listOf("tiny\t2\t0\tobfuscated\tnamed"), Files.readAllLines(out.resolve("mapping.tiny")))
                base = out
            }
        }
        rejectWrongDependencies()
        cli.write("summary.json", mapOf("schemaVersion" to 1, "unknownRoles" to 6, "ambiguousRoles" to 6,
            "duplicateSameTypeUniqueRoles" to 6, "commands" to cli.commandCount, "timings" to cli.timingSummary, "status" to "PASS"))
    }

    private fun importCorpus(): Path {
        val ref = rawType("v1", "RelatedDescriptor")
        val declClass = ref.drop(1).dropLast(1).replace('/', '.')
        val field = oracle.getValue("v1").field(namespace + "RelatedDescriptor", "request", sourceType("WireContract"))
        val method = oracle.getValue("v1").method(namespace + "RelatedDescriptor", "toString", "()Ljava/lang/String;")
        fun annotation(type: String, owner: String, name: String, member: String? = null) = mapOf(
            "nodeRef" to (mapOf("refType" to type, "declClass" to owner) + if (member == null) emptyMap() else mapOf("shortId" to member)), "newName" to name)
        val project = cli.write("manual/project.jadx", mapOf("projectVersion" to 1, "files" to listOf(apk("v1").toString()),
            "codeData" to mapOf("renames" to listOf(
                annotation("CLASS", declClass, roleNames.getValue("descriptor")),
                annotation("FIELD", declClass, "requestMarshallerNote", "${field.name}:${field.type}"),
                annotation("METHOD", declClass, "descriptorRenderingNote", method.name + method.descriptor),
                annotation("CLASS", rawType("v1", "ResearchOnly").drop(1).dropLast(1).replace('/', '.'), "ResearchOnlyTarget")))))
        val out = cli.output.resolve("corpus")
        cli.execute("import-corpus", "analysis", "import-jadx", "--apk", apk("v1"), "--project", project, "--out", out)
        return out.resolve("corpus.json")
    }

    private fun researchUnconfigured(corpusPath: Path, corpus: ManualCorpus): AnalysisResearch {
        val before = cli.result<CorpusTargetPage>("before-research-targets", "analysis", "targets", "--corpus", corpusPath, "--limit", 20)
        assertEquals(setOf("UNCONFIGURED"), before.items.map { it.state }.toSet())
        val dir = cli.output.resolve("research")
        val summary = cli.result<AnalysisResearchResult>("research", "analysis", "research", "--corpus", corpusPath,
            "--target", corpus.targets.joinToString(",") { it.targetId }, "--out", dir)
        val document = cli.read<AnalysisResearch>(dir.resolve("research.json"))
        assertEquals(summary.researchId, document.researchId)
        assertEquals(corpus.corpusId, document.corpusId)
        assertEquals(2, document.targets.size)
        assertFalse(Files.exists(dir.resolve("run.json")))
        assertFalse(Files.exists(dir.resolve("knowledge.json")))
        assertFalse(Files.exists(dir.resolve("mapping.tiny")))
        assertFalse(Files.exists(dir.resolve("reviews")))
        assertFalse(cli.read<JsonObject>(dir.resolve("research.json")).has("resolution"))
        val raw = RawDex.read(apk("v1"))
        document.targets.forEach { result ->
            assertEquals(corpus.annotations.filter { it.ownerDescriptor == result.target.source.descriptor }, result.annotations)
            val actual = raw.classes.getValue(result.target.source.descriptor)
            assertEquals(actual.accessFlags, result.facts.accessFlags)
            assertEquals(actual.superType, result.facts.superType)
            assertEquals(actual.interfaces.toSet(), result.facts.interfaces.toSet())
            assertEquals(actual.fields.map { Triple(it.name, it.type, it.flags) }.toSet(), result.facts.fields.map { Triple(it.name, it.type, it.accessFlags) }.toSet())
            assertEquals(actual.methods.map { it.ref.name + it.ref.descriptor }.toSet(), result.facts.methods.map { it.ref.name + it.ref.descriptor }.toSet())
            assertEquals(document.researchId, result.evidence.runId)
            assertEquals(result.target.source, result.evidence.ref)
            val hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(dir.resolve(result.evidence.javaPath))).joinToString("") { "%02x".format(it) }
            assertEquals(hash, result.evidence.javaSha256)
        }
        val descriptor = document.targets.single { it.target.manualName == roleNames.getValue("descriptor") }
        assertEquals(setOf("CLASS", "FIELD", "METHOD"), descriptor.annotations.map { it.kind }.toSet())
        val rendering = oracle.getValue("v1").method(namespace + "RelatedDescriptor", "toString", "()Ljava/lang/String;")
        val renderingFacts = descriptor.facts.methods.single { it.ref.name == rendering.name && it.ref.descriptor == rendering.descriptor }
        assertTrue(renderingFacts.strings.map { it.literal }.containsAll(listOf("fullMethodName", "requestMarshaller", "responseMarshaller")))
        val put = oracle.getValue("v1").method(namespace + "Description", "put", "(Ljava/lang/String;Ljava/lang/Object;)${sourceType("Description")}")
        assertTrue(renderingFacts.calls.any { it.target.ownerDescriptor == put.owner && it.target.name == put.name && it.target.descriptor == put.descriptor })
        val request = oracle.getValue("v1").field(namespace + "RelatedDescriptor", "request", sourceType("WireContract"))
        assertTrue(renderingFacts.fieldAccesses.any { it.target.ownerDescriptor == request.owner && it.target.name == request.name && it.target.type == request.type })
        cli.execute("unknown-research-target", "analysis", "research", "--corpus", corpusPath, "--target", "manual-does-not-exist",
            "--out", cli.output.resolve("unknown-research"), expectedExit = 2)
        val after = cli.result<CorpusTargetPage>("after-research-targets", "analysis", "targets", "--corpus", corpusPath, "--limit", 20)
        assertEquals(before, after, "Research cannot promote or modify manual targets")
        return document
    }

    private fun rejectWrongDependencies() {
        val missing = cli.write("inputs/missing.json", AnalysisRuleFile(items = listOf(AnalysisRuleItem("missing", strategy = related("descriptor", "missing")))))
        cli.execute("missing-definition", "analysis", "prepare", "--apk", apk("v1"), "--rules", missing,
            "--run", cli.output.resolve("missing-definition"), expectedExit = 2)
        val wrongSpec = StrategySpec("builtin.method-signature", params("parameterTypes" to listOf("Ljava/lang/String;", "Ljava/lang/String;"),
            "returnSameAsOwner" to true, "requiredFlags" to listOf("STATIC")), EntityKind.METHOD, mapOf("owner" to "owner"))
        val producerDefinitions = listOf(AnalysisAnchorDefinition("owner", listOf(Locator("string-use", "RelatedWrongProducer"))),
            AnalysisAnchorDefinition("wrong", strategy = wrongSpec))
        val invalidDefinitions = cli.write("inputs/wrong-producer-definition.json", AnalysisRuleFile(
            items = listOf(AnalysisRuleItem("unrelated", strategy = related("descriptor", "wrong"))), anchors = producerDefinitions))
        cli.execute("wrong-producer-before-resolution", "analysis", "prepare", "--apk", apk("v1"), "--rules", invalidDefinitions,
            "--run", cli.output.resolve("wrong-producer-definition"), expectedExit = 2)
        val producers = cli.write("inputs/wrong-producer.json", AnalysisRuleFile(anchors = producerDefinitions))
        var base: Path? = null
        for (round in 1..2) {
            val dir = cli.output.resolve("wrong-producer-run-$round")
            val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk("v1"), "--rules", producers, "--run", dir)
            base?.let { args.addAll(listOf("--base-knowledge", it.resolve("knowledge.json"))) }
            cli.execute("wrong-producer-$round", *args.toTypedArray())
            val out = cli.output.resolve("wrong-producer-published-$round")
            cli.execute("wrong-producer-publish-$round", "analysis", "publish", "--run", dir, "--out", out)
            val facts = PublishedFixtureAssertions.verify(cli, apk("v1"), out.resolve("knowledge.json"), oracle.getValue("v1"), emptyMap(), mapOf(
                "owner" to ExpectedPublishedAnchor(namespace + "WrongProducer"), "wrong" to ExpectedPublishedAnchor(namespace + "WrongProducer", "create",
                    "(Ljava/lang/String;Ljava/lang/String;)${sourceType("WrongProducer")}")))
            assertEquals(if (round == 1) setOf("owner") else setOf("owner", "wrong"), facts.anchors.map { it.key }.toSet())
            base = out
        }
        val unrelated = cli.write("inputs/unrelated-producer.json", AnalysisRuleFile(items = listOf(AnalysisRuleItem("unrelated", strategy = related("descriptor", "wrong")))))
        cli.execute("unrelated-method-provenance", "analysis", "prepare", "--apk", apk("v1"), "--rules", unrelated,
            "--base-knowledge", base!!.resolve("knowledge.json"), "--run", cli.output.resolve("unrelated-provenance"), expectedExit = 2)
        cli.execute("old-apk-dependency", "analysis", "prepare", "--apk", apk("v2"), "--rules", unrelated,
            "--base-knowledge", base.resolve("knowledge.json"), "--run", cli.output.resolve("old-apk-dependency"), expectedExit = 2)
    }

    private fun assertRpc(proof: Resolution, version: String, methodName: String, signature: String) {
        assertEquals(ResolutionStatus.UNIQUE, proof.status)
        val method = assertNotNull(proof.uniqueMethod)
        val expected = oracle.getValue(version).method(namespace + "RelatedRpcCases", methodName, signature)
        assertEquals(expected.owner, method.owner.descriptor)
        assertEquals(expected.name, method.name)
        assertEquals(expected.descriptor, method.descriptor)
        assertEquals(RawDex.read(apk(version)).apkSha256, proof.apkSha256)
    }
    private fun assertRole(proof: Resolution, version: String, role: String) {
        assertEquals(ResolutionStatus.UNIQUE, proof.status)
        assertEquals(rawType(version, roleTypes.getValue(role)), proof.uniqueRef!!.descriptor)
        assertEquals(setOf("role"), proof.rule.parameters.keySet(), "Business literals must be inherited from the producer rule")
        assertEquals(role, proof.rule.parameters["role"].asString)
        assertEquals("messages.rpc-descriptor", proof.dependencies.getValue("descriptor").rule.strategyId)
    }
    private fun inspect(scene: String, dir: Path, id: String) = cli.result<Array<EvidenceRecord>>("${dir.fileName}-$id-inspect",
        scene, "inspect", "--run", dir, "--task", id).toList()

    private fun verifyPublished(out: Path, version: String, complete: Boolean) {
        val expectedReturn = if (version == "v1") sourceType("RelatedDescriptor") else "Ljava/lang/Object;"
        val memberTruth = mapOf(
            roleNames.getValue("descriptor") to ExpectedPublishedMembers(fields = listOf(
                ExpectedPublishedField("request", sourceType("WireContract")), ExpectedPublishedField("response", sourceType("WireContract"))),
                methods = listOf(ExpectedPublishedMethod("toString", "()Ljava/lang/String;"))),
            roleNames.getValue("builder") to ExpectedPublishedMembers(methods = listOf(ExpectedPublishedMethod("build", "()${sourceType("RelatedDescriptor")}"))))
        val facts = PublishedFixtureAssertions.verify(cli, apk(version), out.resolve("knowledge.json"), oracle.getValue(version),
            roleTypes.map { (role, type) -> roleNames.getValue(role) to namespace + type }.toMap(),
            mapOf("rpc" to ExpectedPublishedAnchor(namespace + "RelatedRpcCases", "getGroupInfo", "()$expectedReturn")), memberTruth)
        assertEquals(if (complete) roleNames.values.toSet() else emptySet(), facts.entries.map { it.name }.toSet())
        assertEquals(setOf("rpc"), facts.anchors.map { it.key }.toSet())
        if (complete) {
            val contract = facts.entries.single { it.name == roleNames.getValue("marshaller") }.clazz
            assertTrue(contract.accessFlags and 0x200 != 0, "The published marshaller role is its declared interface")
            val raw = RawDex.read(apk(version))
            for (impl in listOf("RequestMarshaller", "ResponseMarshaller")) {
                val implementation = raw.classes.getValue(rawType(version, impl))
                assertNotEquals(implementation.descriptor, contract.descriptor)
                assertTrue(contract.descriptor in implementation.interfaces)
            }
        }
        val lines = Files.readAllLines(out.resolve("mapping.tiny"))
        assertEquals(facts.entries.size + 1, lines.size)
        assertTrue(lines.drop(1).all { it.startsWith("c\t") })
        val readback = cli.result<Array<VerifiedRename>>("${out.fileName}-readback", "knowledge", "verify", "--knowledge", out.resolve("knowledge.json"),
            "--apk", apk(version), "--work", out.resolve("readback"))
        assertEquals(facts.entries.map { it.clazz.descriptor }.toSet(), readback.map { it.descriptor }.toSet())
        facts.entries.forEach { entry ->
            val shown = readback.single { it.descriptor == entry.clazz.descriptor }
            val rawName = entry.clazz.descriptor.drop(1).dropLast(1).replace('/', '.')
            assertEquals(rawName, shown.rawName)
            assertEquals(rawName.substringBeforeLast('.', "").let { if (it.isEmpty()) entry.name else "$it.${entry.name}" }, shown.displayedName)
        }
    }
}
