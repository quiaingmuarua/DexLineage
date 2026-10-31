package dev.dexlineage.cli.fixtures

import com.google.gson.JsonObject
import dev.dexlineage.analysis.*
import dev.dexlineage.analysis.messages.ProtoAnalysisCatalog
import dev.dexlineage.messages.MessagesProtoArtifacts
import dev.dexlineage.messages.ProtoFieldCatalogue
import dev.dexlineage.migration.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.zip.ZipFile
import kotlin.test.*

/** Actual protoc lite output, R8, installed CLI and independent raw DEX/R8 truth. No APK execution. */
@Tag("fixture-integration")
class ProtoIntegrationTest {
    private val namespace = "dev.dexlineage.fixture.proto."
    private val names = mapOf("credential" to "FixtureCredentialMessage", "members" to "FixtureMemberMessage")
    private val owners = mapOf("credential" to "CredentialMessage", "members" to "MemberMessage")
    private lateinit var repo: Path
    private lateinit var fixture: Path
    private lateinit var cli: FixtureCli
    private lateinit var manifest: FixtureManifest
    private lateinit var oracles: Map<String, R8Oracle>
    private fun apk(version: String) = repo.resolve(manifest.versions.getValue(version).apk)
    private fun raw(version: String, name: String) = oracles.getValue(version).descriptor(namespace + name)
    private fun params(vararg pairs: Pair<String, Any>) = cli.gson.toJsonTree(pairs.toMap()).asJsonObject

    private fun setup(label: String) {
        fixture = Path.of(System.getProperty("dexlineage.fixtureRoot")).toAbsolutePath()
        repo = fixture.parent.parent
        manifest = FixtureManifest.read(Path.of(System.getProperty("dexlineage.fixtureCases")))
        oracles = manifest.versions.mapValues { (_, value) -> R8Oracle(repo.resolve(value.mapping)) }
        cli = FixtureCli(Path.of(System.getProperty("dexlineage.distributionDir")),
            Path.of(System.getProperty("dexlineage.fixtureResults")).resolve("proto-$label-${UUID.randomUUID()}"), repo)
        preflight()
    }

    private fun preflight() {
        val checks = listOf("v1", "v2").map { version ->
            val source = fixture.resolve("build/generated/source/proto/${version}Release/java/${namespace.replace('.', '/')}ParentMessage.java")
            assertTrue(Files.readString(source).contains("Protobuf Java Version: 3.25.3"), "Pinned protoc must generate the test source")
            val code = RawDex.read(apk(version))
            val oracle = oracles.getValue(version)
            val parent = code.classes.getValue(raw(version, "ParentMessage"))
            assertNotEquals("L${namespace.replace('.', '/')}ParentMessage;", parent.descriptor)
            val descriptor = "(Lcom/google/protobuf/GeneratedMessageLite\$MethodToInvoke;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"
            val method = oracle.method(namespace + "ParentMessage", "dynamicMethod", descriptor)
            assertNotEquals("dynamicMethod", method.name)
            val instructions = parent.methods.single { it.ref == method }.instructions
            val first = if (version == "v1") "credential_" else "authorizationContext_"
            val second = if (version == "v1") "members_" else "identityNodes_"
            val shared = if (version == "v1") "secondaryCredential_" else "backupAuthorization_"
            assertEquals(first, oracle.field(namespace + "ParentMessage", first, "L${namespace.replace('.', '/')}CredentialMessage;").name)
            assertTrue(parent.fields.any { it.name == first && it.type == raw(version, "CredentialMessage") })
            assertTrue(parent.fields.any { it.name == second })
            assertTrue(parent.fields.any { it.name == shared && it.type == raw(version, "CredentialMessage") })
            assertTrue(instructions.mapNotNull { it.literal }.containsAll(listOf(first, second, shared, "fixtureParentAnchor_")),
                "Targeted generated field keep rules must preserve executable RawMessageInfo names")
            assertTrue(instructions.any { it.typeReference == raw(version, "MemberMessage") }, "Repeated element metadata must survive as a real DEX class literal")
            val scalar = if (version == "v1") "retiredCounter_" else "featureEnabled_"
            val absent = if (version == "v1") "featureEnabled_" else "retiredCounter_"
            assertTrue(parent.fields.any { it.name == scalar })
            assertTrue(parent.fields.none { it.name == absent })
            val configuration = Files.readString(repo.resolve(manifest.versions.getValue(version).configuration))
            assertTrue(configuration.contains("-dontshrink") && configuration.contains("-dontoptimize"))
            assertTrue(configuration.contains("class dev.dexlineage.fixture.proto.**"))
            val mapping = Files.readString(repo.resolve(manifest.versions.getValue(version).mapping))
            assertTrue(mapping.contains("# compiler_version: ${manifest.expectedR8Version}"))
            ZipFile(apk(version).toFile()).use { zip ->
                assertTrue(zip.entries().asSequence().none { it.name.endsWith(".proto") || it.name.endsWith(".java") }, "Source schemas must not enter the matcher APK")
                assertNotNull(zip.getEntry("assets/protobuf-LICENSE.txt"), "Published fixture APK carries the runtime's license")
            }
            mapOf("version" to version, "parent" to parent.descriptor, "dispatch" to method, "fieldNames" to listOf(first, second, shared),
                "presentScalar" to scalar, "absentScalar" to absent, "protocVersion" to "3.25.3", "apkSha256" to code.apkSha256)
        }
        listOf("ParentMessage", "CredentialMessage", "MemberMessage", "MapParent", "OneofParent").forEach {
            assertNotEquals(raw("v1", it), raw("v2", it))
        }
        cli.write("preflight.json", mapOf("schemaVersion" to 1, "status" to "PASS", "checks" to checks,
            "limitation" to "Only generated fields in dev.dexlineage.fixture.proto retain names so protoc reflection metadata stays valid with R8 optimization disabled. Classes and methods are renamed."))
    }

    @Test fun `protoc message fields publish through workspace and migrate by stable tags despite renamed fields`() {
        setup("flow")
        val targets = listOf(
            mapOf("key" to "credential", "fieldNumber" to 1, "cardinality" to "singular", "proposedName" to names.getValue("credential")),
            mapOf("key" to "members", "fieldNumber" to 2, "cardinality" to "repeated", "proposedName" to names.getValue("members")),
            mapOf("key" to "missing", "fieldNumber" to 99, "cardinality" to "singular", "proposedName" to "MissingProto"),
            mapOf("key" to "wrong-cardinality", "fieldNumber" to 1, "cardinality" to "repeated", "proposedName" to "WrongCardinality"))
        val config = config("source", "v1", "fixtureParentAnchor_", targets)
        val workspace = cli.output.resolve("workspace")
        val started = cli.execute("analysis-run", "analysis", "run", "--method", "messages.proto-relations", "--config", config,
            "--work", workspace).asJsonObject
        assertEquals("WAITING_REVIEW", started["state"].asString)
        val runDir = Path.of(started["runPath"].asString)
        val run = cli.read<AnalysisRun>(runDir.resolve("run.json"))
        assertEquals(targets.map { it.getValue("key") }.toSet(), run.tasks.map { it.taskId }.toSet(), "Absent and wrong-cardinality targets must remain visible")
        for ((key, owner) in owners) {
            val task = run.tasks.single { it.taskId == key }
            assertEquals(ResolutionStatus.UNIQUE, task.resolution!!.status)
            assertEquals(raw("v1", owner), task.resolution!!.uniqueRef!!.descriptor)
            assertNull(task.request.discoveryKey, "Declared Proto targets must not depend on discovered PASS leads")
        }
        listOf("missing", "wrong-cardinality").forEach { key ->
            assertEquals(ResolutionStatus.NO_MATCH, run.tasks.single { it.taskId == key }.resolution!!.status)
        }
        val discovery = Path.of(started["discoveryPath"].asString).parent
        val catalogue = cli.read<ProtoAnalysisCatalog>(discovery.resolve("proto-catalog.json"))
        assertEquals(4, catalogue.targets.size)
        assertTrue(catalogue.targets.filter { it.key in setOf("missing", "wrong-cardinality") }.all { it.observedTypes.isEmpty() })
        verifyCatalogue(catalogue.fieldCatalogue, "v1")
        val templateFile = Path.of(started["packetPath"].asString).resolve("review-template.json")
        cli.execute("template-not-review", "analysis", "submit", "--run", runDir, "--review", templateFile, expectedExit = 2)
        val waiting = cli.execute("resume-unreviewed", "analysis", "resume", "--work", workspace).asJsonObject
        assertEquals("WAITING_REVIEW", waiting["state"].asString)
        val template = cli.read<AnalysisReviewBatch>(templateFile)
        val reviews = template.items.filter { it.taskId in owners }.map { item -> item.copy(action = ReviewAction.ACCEPT,
            level = Confidence.HIGH, name = names.getValue(item.taskId),
            rationale = "Self-authored Proto role at the declared field number/cardinality independently verified against R8 source identity.",
            unverified = listOf("Static fixture truth, not Agent judgment, runtime behavior or restoration of arbitrary Proto schemas.")) }
        assertEquals(2, reviews.size)
        val review = cli.write("reviews/source.json", template.copy(items = reviews))
        cli.execute("submit", "analysis", "submit", "--run", runDir, "--review", review)
        val complete = cli.execute("resume-publish", "analysis", "resume", "--work", workspace).asJsonObject
        assertEquals("COMPLETE", complete["state"].asString)
        val sourceFile = Path.of(complete["knowledgePath"].asString)
        val source = cli.read<VersionKnowledge>(sourceFile)
        verifyPublished(sourceFile, "v1")
        val publishedCatalogue = cli.read<ProtoAnalysisCatalog>(sourceFile.parent.resolve("proto-catalog.json"))
        assertEquals(4, publishedCatalogue.targets.size)
        assertTrue(publishedCatalogue.targets.filter { it.key in setOf("missing", "wrong-cardinality") }.all { it.resolution == "NO_MATCH" && it.state == "INVALID" })

        var targetBase: Path? = null
        var previous: VersionKnowledge? = null
        for (round in 1..3) {
            val dir = cli.output.resolve("target-run-$round")
            val args = mutableListOf<Any>("migration", "prepare", "--knowledge", sourceFile, "--source-apk", apk("v1"), "--target-apk", apk("v2"), "--run", dir)
            targetBase?.let { args.addAll(listOf("--target-base", it)) }
            cli.execute("migration-$round-prepare", *args.toTypedArray())
            val migration = cli.read<MigrationRun>(dir.resolve("run.json"))
            assertEquals(2, migration.tasks.size)
            if (round == 1) assertTrue(migration.tasks.all { it.executionState == MigrationExecutionState.WAITING_DEPENDENCY })
            if (round == 2) {
                val items = migration.tasks.map { task ->
                    val key = names.entries.single { it.value == task.entry.name }.key
                    assertEquals(ResolutionStatus.UNIQUE, task.resolution!!.status)
                    assertEquals(raw("v2", owners.getValue(key)), task.resolution!!.uniqueRef!!.descriptor)
                    assertEquals(task.entry.ruleRevision, task.rule)
                    val evidence = cli.result<Array<EvidenceRecord>>("migration-inspect-$key", "migration", "inspect", "--run", dir, "--task", task.taskId)
                    MigrationReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT, Confidence.HIGH, true,
                        "Source-authored message role remains at the same wire tag/cardinality after generated field names and R8 identities change.",
                        listOf("Parent field names and declaration order change; an unrelated scalar is removed and another added."),
                        listOf("Static fixture semantics only; generated field names are deliberately kept in this package to preserve RawMessageInfo."), evidence.map { it.evidenceId })
                }
                val file = cli.write("reviews/migration.json", MigrationReviewBatch(runId = migration.runId, sourceKnowledgeId = source.knowledgeId,
                    sourceApkSha256 = migration.sourceApk.sha256, targetApkSha256 = migration.targetApk.sha256, items = items))
                cli.execute("migration-submit", "migration", "submit", "--run", dir, "--review", file)
            }
            if (round == 3) assertTrue(migration.tasks.all { it.executionState == MigrationExecutionState.INHERITED }, "Third round tests continuation, not a claimed extra matching dependency")
            val out = cli.output.resolve("target-published-$round")
            cli.execute("migration-$round-publish", "migration", "publish", "--run", dir, "--out", out)
            val file = out.resolve("knowledge.json")
            val knowledge = cli.read<VersionKnowledge>(file)
            if (round == 1) {
                assertTrue(knowledge.entries.isEmpty())
                assertEquals(source.entries.map { it.semanticId }.toSet(), knowledge.unresolved.map { it.entry.semanticId }.toSet())
                PublishedFixtureAssertions.verify(cli, apk("v2"), file, oracles.getValue("v2"), emptyMap(), parentTruth("ParentMessage"))
            } else {
                verifyPublished(file, "v2")
                assertEquals(source.entries.map { it.semanticId }.toSet(), knowledge.entries.map { it.semanticId }.toSet())
                knowledge.entries.forEach { e ->
                    val old = source.entries.single { it.semanticId == e.semanticId }
                    assertEquals(old.ruleRevision, e.ruleRevision)
                    assertNotEquals(old.binding, e.binding)
                    assertNotEquals(old.resolution!!.resolutionId, e.resolution!!.resolutionId)
                }
                verifyCatalogue(rawCatalogue(out), "v2")
            }
            if (round == 3) {
                assertEquals(previous!!.entries, knowledge.entries)
                assertEquals(Files.readString(targetBase!!.parent.resolve("mapping.tiny")), Files.readString(out.resolve("mapping.tiny")))
                val replay = cli.output.resolve("migration-replay")
                cli.execute("migration-replay", "migration", "publish", "--run", dir, "--at", out.resolve("report.json"), "--out", replay)
                assertEquals(Files.readString(file), Files.readString(replay.resolve("knowledge.json")))
                PublishedFixtureAssertions.verify(cli, apk("v2"), replay.resolve("knowledge.json"), oracles.getValue("v2"), aliasTruth(), parentTruth("ParentMessage"))
            }
            targetBase = file
            previous = knowledge
        }
        cli.write("summary.json", mapOf("schemaVersion" to 1, "status" to "PASS", "analysisTargets" to 4, "publishedClasses" to 2,
            "migrationRounds" to 3, "roundThree" to "inherited continuation", "commands" to cli.commandCount, "timings" to cli.timingSummary))
    }

    @Test fun `map and oneof metadata remain unknown with every configured target retained`() {
        setup("unsupported")
        for ((owner, marker) in listOf("MapParent" to "fixtureMapAnchor_", "OneofParent" to "fixtureOneofAnchor_")) {
            val targets = listOf(
                mapOf("key" to "field-one", "fieldNumber" to 1, "cardinality" to "singular", "proposedName" to "MustNotPublish"),
                mapOf("key" to "absent", "fieldNumber" to 99, "cardinality" to "repeated", "proposedName" to "MustRemainVisible"))
            val config = config(owner, "v2", marker, targets)
            val started = cli.execute("$owner-run", "analysis", "run", "--method", "messages.proto-relations", "--config", config,
                "--work", cli.output.resolve("$owner-workspace")).asJsonObject
            assertEquals("COMPLETE", started["state"].asString, "Invalid selected targets are reported and do not demand meaningless Review")
            val dir = Path.of(started["runPath"].asString)
            val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
            assertEquals(2, run.tasks.size)
            run.tasks.forEach { task ->
                assertEquals(ResolutionStatus.UNKNOWN, task.resolution!!.status)
                assertTrue(task.resolution!!.candidates.isEmpty(), "Unsupported metadata cannot leak partial prefix candidates")
                assertTrue(task.resolution!!.unresolvedPaths.orEmpty().isNotEmpty())
            }
            val task = run.tasks.first()
            val review = cli.write("reviews/$owner-invalid.json", AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256,
                items = listOf(AnalysisReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT,
                    "MustNotPublish", Confidence.HIGH, "Deliberate invalid acceptance attempt."))))
            cli.execute("$owner-reject-review", "analysis", "submit", "--run", dir, "--review", review, expectedExit = 2)
            val knowledge = Path.of(started["knowledgePath"].asString)
            val facts = PublishedFixtureAssertions.verify(cli, apk("v2"), knowledge, oracles.getValue("v2"), emptyMap(), parentTruth(owner))
            assertTrue(facts.entries.isEmpty())
            assertEquals(listOf("tiny\t2\t0\tobfuscated\tnamed"), Files.readAllLines(knowledge.parent.resolve("mapping.tiny")))
            val catalogue = cli.read<ProtoAnalysisCatalog>(knowledge.parent.resolve("proto-catalog.json"))
            assertEquals(2, catalogue.targets.size)
            assertTrue(catalogue.fieldCatalogue.fields.isEmpty())
            assertTrue(catalogue.fieldCatalogue.unresolvedPaths.isNotEmpty())
            assertTrue(catalogue.targets.all { it.resolution == "UNKNOWN" && it.state == "INVALID" && it.observedTypes.isEmpty() })
        }
    }

    private fun config(label: String, version: String, marker: String, targets: List<Map<String, Any>>): Path {
        val profile = cli.write("inputs/$label-profile.json", AnalysisProfile(id = "proto-$label",
            strategy = StrategySpec("messages.proto-fields", requires = mapOf("parent" to "parent.message")),
            method = AnalysisMethodSpec("messages.proto-relations", params("targets" to targets))))
        val seed = cli.write("inputs/$label-seed.json", AnalysisRuleFile(anchors = listOf(AnalysisAnchorDefinition("parent.message",
            locators = listOf(Locator("string-use", marker))))))
        return cli.write("inputs/$label-config.json", mapOf("schemaVersion" to SCHEMA_VERSION, "apk" to apk(version).toString(),
            "profile" to profile.toString(), "seedRules" to seed.toString()))
    }

    private fun verifyCatalogue(catalogue: ProtoFieldCatalogue, version: String) {
        assertEquals(raw(version, "ParentMessage"), catalogue.parent.descriptor)
        assertTrue(catalogue.unresolvedPaths.isEmpty())
        assertTrue(catalogue.metadata.isNotEmpty() && catalogue.metadata.all { it.status == "RESOLVED" })
        val credential = catalogue.fields.single { it.fieldNumber == 1 }
        assertEquals("singular", credential.cardinality)
        assertEquals(raw(version, "CredentialMessage"), credential.relatedType!!.descriptor)
        assertEquals(if (version == "v1") "credential_" else "authorizationContext_", credential.fieldName)
        val members = catalogue.fields.single { it.fieldNumber == 2 }
        assertEquals("repeated", members.cardinality)
        assertEquals(raw(version, "MemberMessage"), members.relatedType!!.descriptor)
        assertEquals(if (version == "v1") "members_" else "identityNodes_", members.fieldName)
        val sharedCredential = catalogue.fields.single { it.fieldNumber == 3 }
        assertEquals("singular", sharedCredential.cardinality)
        assertEquals(credential.relatedType, sharedCredential.relatedType, "Distinct field roles may share one message entity")
        assertEquals(if (version == "v1") "secondaryCredential_" else "backupAuthorization_", sharedCredential.fieldName)
        assertTrue(catalogue.fields.any { it.fieldNumber == if (version == "v1") 7 else 9 })
        assertTrue(catalogue.fields.none { it.fieldNumber == if (version == "v1") 9 else 7 })
    }

    private fun rawCatalogue(packageDir: Path): ProtoFieldCatalogue {
        val report = cli.read<JsonObject>(packageDir.resolve("report.json"))
        val reference = report.getAsJsonArray("methodArtifacts").map { it.asJsonObject }.single { it["kind"].asString == MessagesProtoArtifacts.KIND }
        val path = Path.of(reference["path"].asString)
        assertFalse(path.isAbsolute, "Proto diagnostics must move with the published package")
        return cli.read(packageDir.resolve(path))
    }
    private fun parentTruth(owner: String) = mapOf("parent.message" to ExpectedPublishedAnchor(namespace + owner))
    private fun aliasTruth() = names.entries.associate { (key, alias) -> alias to namespace + owners.getValue(key) }
    private fun verifyPublished(file: Path, version: String) {
        val facts = PublishedFixtureAssertions.verify(cli, apk(version), file, oracles.getValue(version), aliasTruth(), parentTruth("ParentMessage"))
        assertEquals(2, facts.entries.size)
        assertEquals(3, Files.readAllLines(file.parent.resolve("mapping.tiny")).size)
        val shown = cli.result<Array<VerifiedRename>>("${file.parent.fileName}-readback", "knowledge", "verify", "--knowledge", file,
            "--apk", apk(version), "--work", cli.output.resolve("${file.parent.fileName}-readback"))
        assertEquals(facts.entries.map { it.clazz.descriptor }.toSet(), shown.map { it.descriptor }.toSet())
    }
}
