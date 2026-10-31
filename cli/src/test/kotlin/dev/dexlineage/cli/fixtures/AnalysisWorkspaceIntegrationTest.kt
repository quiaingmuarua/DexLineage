package dev.dexlineage.cli.fixtures

import com.google.gson.JsonObject
import dev.dexlineage.analysis.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.test.*

/** The production workspace orchestrates the same matching/review/publication path as the individual commands. */
@Tag("fixture-integration")
class AnalysisWorkspaceIntegrationTest {
    private val namespace = "dev.dexlineage.fixture.theme."
    private val services = listOf("Group", "Registration", "Messaging", "Abuse").map { "fixture.theme.$it" }
    private val aliases = linkedMapOf(
        "SeedRequest" to "FixtureSeedRequest", "SeedResponse" to "FixtureSeedResponse",
        "GroupRequest" to "FixtureGroupRequest", "GroupResponse" to "FixtureGroupResponse",
        "RegistrationRequest" to "FixtureRegistrationRequest", "RegistrationResponse" to "FixtureRegistrationResponse",
        "SharedRecord" to "FixtureSharedRecord", "AbuseResponse" to "FixtureAbuseResponse",
        "DuplicateRequest" to "FixtureDuplicateRequest", "DuplicateResponse" to "FixtureDuplicateResponse")

    @Test fun `Messages method creates review packets and publishes after explicit resume in both R8 versions`() {
        val fixture = Path.of(System.getProperty("dexlineage.fixtureRoot"))
        val repo = fixture.parent.parent
        val manifest = FixtureManifest.read(Path.of(System.getProperty("dexlineage.fixtureCases")))
        val cli = FixtureCli(Path.of(System.getProperty("dexlineage.distributionDir")),
            Path.of(System.getProperty("dexlineage.fixtureResults")).resolve("analysis-workspace-${UUID.randomUUID()}"), repo)
        FixturePreflight.verify(fixture, Path.of(System.getProperty("dexlineage.fixtureCases")), cli.output.resolve("preflight"))
        val anchors = AnalysisRuleFile(anchors = listOf(
            AnalysisAnchorDefinition("rpc.seed", strategy = StrategySpec("messages.rpc-descriptor",
                json(cli, "service" to "fixture.theme.Group", "rpc" to "Seed"), EntityKind.METHOD)),
            AnalysisAnchorDefinition("rpc.descriptor", strategy = StrategySpec("messages.rpc-related-type",
                json(cli, "role" to "descriptor"), requires = mapOf("descriptor" to "rpc.seed"))),
            AnalysisAnchorDefinition("rpc.full-name", strategy = StrategySpec("grpc-java.full-method-name",
                resultKind = EntityKind.METHOD, requires = mapOf("descriptor" to "rpc.descriptor")))))
        val seed = cli.write("inputs/seed.json", anchors)
        val profile = cli.write("inputs/profile.json", mapOf("schemaVersion" to SCHEMA_VERSION, "id" to "workspace-fixture",
            "strategy" to StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "rpc.full-name")),
            "rpcDrafts" to mapOf("reviewServices" to services)))
        for (version in listOf("v1", "v2")) {
            val apk = repo.resolve(manifest.versions.getValue(version).apk)
            val oracle = R8Oracle(repo.resolve(manifest.versions.getValue(version).mapping))
            val config = cli.write("inputs/$version-config.json", mapOf("schemaVersion" to SCHEMA_VERSION,
                "apk" to apk.toString(), "profile" to profile.toString(), "seedRules" to seed.toString()))
            val work = cli.output.resolve("$version-workspace")
            val started = cli.execute("$version-run", "analysis", "run", "--method", "messages.grpc", "--config", config, "--work", work).asJsonObject
            assertEquals("WAITING_REVIEW", started["state"].asString)
            val runDir = Path.of(started["runPath"].asString)
            val packetDir = Path.of(started["packetPath"].asString)
            val run = cli.read<AnalysisRun>(runDir.resolve("run.json"))
            val template = cli.read<AnalysisReviewBatch>(packetDir.resolve("review-template.json"))
            assertEquals(run.runId, template.runId)
            assertTrue(Files.isRegularFile(packetDir.resolve("summary.md")))
            assertTrue(Files.isRegularFile(packetDir.resolve("review-packet.json")))
            assertTrue(template.items.none { it.action == ReviewAction.ACCEPT && it.level == Confidence.HIGH })
            cli.execute("$version-draft-is-not-review", "analysis", "submit", "--run", runDir,
                "--review", packetDir.resolve("review-template.json"), expectedExit = 2)
            val status = cli.execute("$version-status", "analysis", "status", "--work", work).asJsonObject
            assertEquals("WAITING_REVIEW", status["state"].asString)
            val pending = cli.execute("$version-resume-before-review", "analysis", "resume", "--work", work).asJsonObject
            assertEquals("WAITING_REVIEW", pending["state"].asString)
            assertEquals(started["runPath"], pending["runPath"], "A fresh process must reuse the completed matching stage")

            // Source-authored identities are checked BEFORE semantic fixture truth is submitted.
            val expected = aliases.mapKeys { oracle.descriptor(namespace + it.key) }
            val eligible = run.tasks.filter { task -> task.resolution?.status == ResolutionStatus.UNIQUE &&
                task.rule.parameters.getAsJsonArray("selectors").any { it.asJsonObject["service"].asString in services } }
            assertEquals(expected.keys, eligible.map { it.resolution!!.uniqueRef!!.descriptor }.toSet())
            assertTrue(run.tasks.any { it.resolution?.status == ResolutionStatus.AMBIGUOUS })
            assertTrue(run.tasks.any { it.resolution?.status == ResolutionStatus.UNKNOWN })
            assertTrue(run.tasks.any { task -> task.rule.parameters.getAsJsonArray("selectors").all {
                it.asJsonObject["service"].asString !in services } }, "Review selection must not narrow matching")
            val byId = template.items.associateBy { it.taskId }
            val reviews = eligible.map { task ->
                val draft = assertNotNull(byId[task.taskId])
                assertEquals(task.resolution!!.resolutionId, draft.resolutionId)
                assertEquals(task.rule.revisionId, draft.ruleRevisionId)
                assertTrue(draft.evidenceIds.isNotEmpty())
                draft.copy(action = ReviewAction.ACCEPT, level = Confidence.HIGH,
                    name = expected.getValue(task.resolution!!.uniqueRef!!.descriptor),
                    rationale = "Predefined fixture RPC role verified independently with R8 source identity before submission.",
                    unverified = listOf("Static fixture truth; this does not evaluate Agent semantic judgment or runtime behavior."))
            }
            val bad = reviews.first().copy(resolutionId = "0".repeat(64))
            val badFile = cli.write("reviews/$version-wrong-proof.json", template.copy(items = listOf(bad)))
            cli.execute("$version-wrong-proof", "analysis", "submit", "--run", runDir, "--review", badFile, expectedExit = 2)
            val reviewFile = cli.write("reviews/$version.json", template.copy(items = reviews))
            cli.execute("$version-submit", "analysis", "submit", "--run", runDir, "--review", reviewFile)
            cli.execute("$version-submit-idempotent", "analysis", "submit", "--run", runDir, "--review", reviewFile)
            val finished = cli.execute("$version-resume-publish", "analysis", "resume", "--work", work).asJsonObject
            assertEquals("COMPLETE", finished["state"].asString)
            val knowledgeFile = Path.of(finished["knowledgePath"].asString)
            val published = cli.read<VersionKnowledge>(knowledgeFile)
            assertEquals(aliases.values.toSet(), published.entries.map { it.name }.toSet())
            assertEquals(aliases.size, published.entries.map { it.binding }.distinct().size)
            val anchorTruth = mapOf(
                "rpc.seed" to ExpectedPublishedAnchor(namespace + "ThemeRpcCases", "seed",
                    if (version == "v1") "()L${namespace.replace('.', '/')}ThemeDescriptor;" else "()Ljava/lang/Object;"),
                "rpc.descriptor" to ExpectedPublishedAnchor(namespace + "ThemeDescriptor"),
                "rpc.full-name" to ExpectedPublishedAnchor(namespace + "ThemeDescriptor", "name", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"))
            PublishedFixtureAssertions.verify(cli, apk, knowledgeFile, oracle,
                aliases.entries.associate { it.value to namespace + it.key }, anchorTruth)
            cli.execute("$version-jadx-readback", "knowledge", "verify", "--knowledge", knowledgeFile,
                "--apk", apk, "--work", cli.output.resolve("$version-readback"))
            val repeat = cli.execute("$version-resume-complete", "analysis", "resume", "--work", work).asJsonObject
            assertEquals(finished["knowledgePath"], repeat["knowledgePath"])
            val replay = cli.output.resolve("$version-publication-replay")
            cli.execute("$version-replay", "analysis", "publish", "--run", runDir, "--at", knowledgeFile.parent.resolve("report.json"), "--out", replay)
            assertEquals(Files.readString(knowledgeFile), Files.readString(replay.resolve("knowledge.json")))
            assertEquals(Files.readString(knowledgeFile.parent.resolve("mapping.tiny")), Files.readString(replay.resolve("mapping.tiny")))
            if (version == "v2") {
                val relocated = cli.output.resolve("relocated-package")
                Files.walk(knowledgeFile.parent).use { paths -> paths.forEach { source ->
                    val target = relocated.resolve(knowledgeFile.parent.relativize(source).toString())
                    if (Files.isDirectory(source)) Files.createDirectories(target) else Files.copy(source, target)
                } }
                val report = cli.read<JsonObject>(relocated.resolve("report.json"))
                assertTrue(report.getAsJsonArray("methodArtifacts").all { !Path.of(it.asJsonObject["path"].asString).isAbsolute },
                    "Scenario artifacts in a publication must move with the package")
                val relocatedProfile = cli.write("inputs/relocated-profile.json", AnalysisProfile(id = "relocated-base",
                    discovery = Locator("string-use", "theme-canonical-request"), locatorTemplate = LocatorTemplate("string-use", "literal")))
                val relocatedConfig = cli.write("inputs/relocated-config.json", mapOf("schemaVersion" to SCHEMA_VERSION,
                    "apk" to apk.toString(), "profile" to relocatedProfile.toString(), "baseKnowledge" to relocated.resolve("knowledge.json").toString()))
                val loaded = cli.execute("relocated-base", "analysis", "run", "--method", "profile", "--config", relocatedConfig,
                    "--work", cli.output.resolve("relocated-workspace")).asJsonObject
                assertEquals("WAITING_REVIEW", loaded["state"].asString)
                val loadedRun = cli.read<AnalysisRun>(Path.of(loaded["runPath"].asString).resolve("run.json"))
                assertEquals(published.knowledgeId, loadedRun.baseKnowledge!!.knowledgeId)
                assertEquals(published.entries.single { it.binding.descriptor == oracle.descriptor(namespace + "GroupRequest") }.semanticId,
                    loadedRun.tasks.single().semanticId)
            }
        }
    }

    @Test fun `profile method reuses the same workspace and packet path for private logger matching`() {
        val fixture = Path.of(System.getProperty("dexlineage.fixtureRoot"))
        val repo = fixture.parent.parent
        val manifest = FixtureManifest.read(Path.of(System.getProperty("dexlineage.fixtureCases")))
        val cli = FixtureCli(Path.of(System.getProperty("dexlineage.distributionDir")),
            Path.of(System.getProperty("dexlineage.fixtureResults")).resolve("profile-workspace-${UUID.randomUUID()}"), repo)
        val scenario = manifest.cases.single { it.id == "privateCache" }
        val expected = scenario.versions.getValue("v1")
        val oracle = R8Oracle(repo.resolve(manifest.versions.getValue("v1").mapping))
        val factors = listOf(FactorSpec("field-flags", requiredFlags = listOf("STATIC", "FINAL")),
            FactorSpec("invocation-kind", invocationKind = "STATIC"),
            FactorSpec("method-signature", parameterTypes = listOf("Ljava/lang/String;", "Ljava/lang/String;"), returnSameAsField = true),
            FactorSpec("argument-string", index = 1, value = scenario.component), FactorSpec("assignment-owner"))
        val profile = cli.write("profile.json", AnalysisProfile(id = "private-logger-workspace",
            discovery = Locator("field-initializer", scenario.component, factors, listOf(CaptureSpec("component", 1))),
            nameCapture = "component", locatorTemplate = LocatorTemplate("field-initializer", "component",
                factors.map { if (it.kind == "argument-string") it.copy(value = null, valueFromCapture = "component") else it })))
        val apk = repo.resolve(manifest.versions.getValue("v1").apk)
        val config = cli.write("config.json", mapOf("schemaVersion" to SCHEMA_VERSION, "apk" to apk.toString(), "profile" to profile.toString()))
        val work = cli.output.resolve("work")
        val started = cli.execute("run", "analysis", "run", "--method", "profile", "--config", config, "--work", work).asJsonObject
        assertEquals("WAITING_REVIEW", started["state"].asString)
        val runDir = Path.of(started["runPath"].asString)
        val run = cli.read<AnalysisRun>(runDir.resolve("run.json"))
        assertEquals(oracle.descriptor(expected.owners.single()), run.tasks.single().resolution!!.uniqueRef!!.descriptor)
        val template = cli.read<AnalysisReviewBatch>(Path.of(started["packetPath"].asString).resolve("review-template.json"))
        val review = template.copy(items = listOf(template.items.single().copy(action = ReviewAction.ACCEPT,
            level = Confidence.HIGH, name = scenario.semanticAlias, rationale = "Source-authored private logger identity verified against R8 mapping.",
            unverified = listOf("Static integration truth only."))))
        val file = cli.write("review.json", review)
        cli.execute("submit", "analysis", "submit", "--run", runDir, "--review", file)
        val finished = cli.execute("resume", "analysis", "resume", "--work", work).asJsonObject
        assertEquals("COMPLETE", finished["state"].asString)
        val published = Path.of(finished["knowledgePath"].asString)
        PublishedFixtureAssertions.verify(cli, apk, published, oracle, mapOf(scenario.semanticAlias to expected.owners.single()))
        cli.execute("readback", "knowledge", "verify", "--knowledge", published, "--apk", apk, "--work", cli.output.resolve("readback"))
        val changed = cli.gson.toJsonTree(cli.read<JsonObject>(config)).asJsonObject.apply { addProperty("apk", "changed.apk") }
        Files.writeString(config, cli.gson.toJson(changed))
        cli.execute("changed-input", "analysis", "resume", "--work", work, expectedExit = 2)
    }

    private fun json(cli: FixtureCli, vararg entries: Pair<String, Any>) = cli.gson.toJsonTree(entries.toMap()).asJsonObject
}
