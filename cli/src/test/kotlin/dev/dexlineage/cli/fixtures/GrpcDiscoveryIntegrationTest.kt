package dev.dexlineage.cli.fixtures

import dev.dexlineage.analysis.*
import dev.dexlineage.knowledge.KnowledgeFiles
import dev.dexlineage.migration.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.test.*

/** Real APKs and CLI processes; source identities and semantic conclusions are test-authored. */
@Tag("fixture-integration")
class GrpcDiscoveryIntegrationTest {
    private val namespace = "dev.dexlineage.fixture.theme."
    private val services = listOf("Group", "Registration", "Messaging", "Abuse").map { "fixture.theme.$it" }
    private val accepted = linkedMapOf(
        "SeedRequest" to "FixtureSeedRequest", "SeedResponse" to "FixtureSeedResponse",
        "GroupRequest" to "CanonicalGroupRequest", "GroupResponse" to "FixtureGroupResponse",
        "RegistrationRequest" to "FixtureRegistrationRequest", "RegistrationResponse" to "FixtureRegistrationResponse",
        "SharedRecord" to "FixtureSharedRecord", "AbuseResponse" to "FixtureAbuseResponse",
        "DuplicateRequest" to "FixtureDuplicateRequest", "DuplicateResponse" to "FixtureDuplicateResponse")
    private val unreviewed = setOf("OutsideRequest", "OutsideResponse")
    private val ambiguous = setOf("ConflictFirstRequest", "ConflictFirstResponse", "ConflictSecondRequest", "ConflictSecondResponse")
    private val unknown = setOf("UnknownRequest", "UnknownResponse")
    private lateinit var cli: FixtureCli
    private lateinit var root: Path
    private lateinit var manifest: FixtureManifest
    private lateinit var oracle: Map<String, R8Oracle>
    private fun apk(version: String) = root.resolve(manifest.versions.getValue(version).apk)
    private fun type(name: String) = "L${(namespace + name).replace('.', '/')};"
    private fun raw(version: String, name: String) = oracle.getValue(version).descriptor(namespace + name)
    private fun parameters(vararg pairs: Pair<String, Any>) = cli.gson.toJsonTree(pairs.toMap()).asJsonObject
    private fun knowledge(out: Path) = out.resolve("knowledge.json")

    private fun setup() {
        root = Path.of(System.getProperty("dexlineage.fixtureRoot")).toAbsolutePath().parent.parent
        manifest = FixtureManifest.read(Path.of(System.getProperty("dexlineage.fixtureCases")))
        oracle = manifest.versions.mapValues { (_, v) -> R8Oracle(root.resolve(v.mapping)) }
        cli = FixtureCli(Path.of(System.getProperty("dexlineage.distributionDir")),
            Path.of(System.getProperty("dexlineage.fixtureResults")).resolve("grpc-discovery-${UUID.randomUUID()}"), root)
        val checks = listOf("v1", "v2").map { version ->
            val dex = RawDex.read(apk(version))
            val factory = oracle.getValue(version).method(namespace + "ThemeDescriptor", "name", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
            assertNotEquals("name", factory.name)
            assertTrue(dex.classes.getValue(factory.owner).methods.any { it.ref == factory })
            val rpc = oracle.getValue(version).method(namespace + "ThemeRpcCases", "groupState",
                if (version == "v1") "()${type("ThemeDescriptor")}" else "()Ljava/lang/Object;")
            val calls = dex.classes.getValue(rpc.owner).methods.single { it.ref == rpc }.instructions
            assertTrue(calls.any { it.literal == "fixture.theme.Group" })
            assertTrue(calls.any { it.literal == "FetchState" })
            val requestField = oracle.getValue(version).field(namespace + "ThemeBuilder", "request", type("ThemeWire"))
            val responseField = oracle.getValue(version).field(namespace + "ThemeBuilder", "response", type("ThemeWire"))
            assertNotEquals("request", requestField.name)
            val roleAssignments = calls.filter { it.opcode.name.startsWith("IPUT") && it.fieldOwner == requestField.owner &&
                it.fieldName in setOf(requestField.name, responseField.name) }.map { it.fieldName }
            assertEquals(if (version == "v1") listOf(requestField.name, responseField.name) else listOf(responseField.name, requestField.name),
                roleAssignments, "The declared version perturbation must survive in DEX field assignments")
            if (version == "v1") {
                val wrapper = oracle.getValue(version).method(namespace + "ThemeMarshallers", "request", "(${type("ThemeRecord")})${type("ThemeWire")}")
                assertTrue(calls.any { it.method == wrapper }, "v1 must retain the marshaller factory call")
            } else assertTrue(calls.any { it.method?.owner == raw(version, "ThemeRequestMarshaller") && it.method?.name == "<init>" },
                "v2 must retain direct marshaller construction")
            val deepConfig = oracle.getValue(version).method(namespace + "ThemeRpcCases", "deepConfiguration", "(Ljava/util/Map;)Ljava/lang/Object;")
            val configCalls = dex.classes.getValue(deepConfig.owner).methods.single { it.ref == deepConfig }.instructions.mapNotNull { it.method }
            assertTrue(configCalls.count { it.owner in setOf("Ljava/util/Map;", "Ljava/util/List;") && it.name == "get" } >= 8,
                "The configuration regression must retain its deep getter chain in DEX")
            val guard = oracle.getValue(version).method(namespace + "ThemeChecks", "check", "(ZLjava/lang/String;Ljava/lang/Object;)V")
            assertNotEquals("check", guard.name)
            assertTrue(guard in configCalls && factory in configCalls)
            mapOf("version" to version, "factory" to factory, "rpc" to rpc, "requestField" to requestField,
                "roleAssignmentOrder" to roleAssignments, "deepConfiguration" to deepConfig, "diagnosticGuard" to guard,
                "apkSha256" to dex.apkSha256)
        }
        (accepted.keys + ambiguous + unknown + unreviewed + "ThemeDescriptor").forEach {
            assertNotEquals(raw("v1", it), raw("v2", it), "R8 must change the original identity for $it")
        }
        cli.write("fixture-shape.json", mapOf("schemaVersion" to 1, "status" to "PASS", "checks" to checks))
    }

    @Test fun `whole APK RPC discovery groups roles and reuses explicitly referenced identities after fresh review`() {
        setup()
        val references = canonicalReferences()
        val published = mutableMapOf<String, Path>()
        val bases = mutableMapOf<String, Path>()
        val generated = mutableMapOf<String, Path>()
        for (version in listOf("v1", "v2")) {
            val base = seedAnchors(version)
            bases[version] = base
            val profile = cli.write("inputs/$version-profile.json", mapOf("schemaVersion" to SCHEMA_VERSION, "id" to "fixture-rpc-topic",
                "strategy" to StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "rpc.full-name")),
                "rpcDrafts" to mapOf("reviewServices" to services, "requestSuffix" to "Request", "responseSuffix" to "Response")))
            val discoveryDir = cli.output.resolve("$version-discovery")
            cli.execute("$version-discover", "analysis", "discover", "--apk", apk(version), "--profile", profile,
                "--base-knowledge", knowledge(base), "--out", discoveryDir)
            assertTrue(Files.isRegularFile(discoveryDir.resolve("rpc-catalog.json")))
            val discovery = cli.read<AnalysisDiscovery>(discoveryDir.resolve("discovery.json"))
            val calls = assertNotNull(discovery.rpcCalls)
            assertEquals((services + "fixture.theme.Outside").toSet(), calls.mapNotNull { it.service }.toSet())
            val configuration = calls.single { it.rpc == "ConfigurationOnly" }
            assertEquals("NON_CONSTRUCTION", configuration.status)
            assertTrue(configuration.requestTypes.isEmpty() && configuration.responseTypes.isEmpty(),
                "A configuration string call is not a message role")
            val deepConfig = oracle.getValue(version).method(namespace + "ThemeRpcCases", "deepConfiguration", "(Ljava/util/Map;)Ljava/lang/Object;")
            val dynamicConfiguration = calls.single { it.source.owner.descriptor == deepConfig.owner &&
                it.source.name == deepConfig.name && it.source.descriptor == deepConfig.descriptor }
            assertNull(dynamicConfiguration.service)
            assertNull(dynamicConfiguration.rpc)
            assertEquals("NON_CONSTRUCTION", dynamicConfiguration.status,
                "Deep dynamic name inputs and a proven diagnostic guard cannot poison unrelated RPC resolutions")
            assertTrue(dynamicConfiguration.requestTypes.isEmpty() && dynamicConfiguration.responseTypes.isEmpty())
            val escaped = calls.single { it.rpc == "EscapedName" }
            assertEquals("UNRESOLVED_CONSTRUCTION", escaped.status)
            assertTrue(escaped.requestTypes.isEmpty() && escaped.responseTypes.isEmpty(),
                "An escaped name must not invent a Proto candidate")
            val opaque = calls.single { it.rpc == "OpaqueHelper" }
            assertEquals("UNRESOLVED_CONSTRUCTION", opaque.status,
                "An ordinary application helper cannot be assumed to be a pure diagnostic guard")
            assertTrue(opaque.requestTypes.isEmpty() && opaque.responseTypes.isEmpty())
            val duplicate = calls.filter { it.rpc == "Duplicate" }
            assertEquals(2, duplicate.size, "Both real call sites must be retained before entity deduplication")
            assertEquals(setOf(raw(version, "DuplicateRequest")), duplicate.flatMap { it.requestTypes }.map { it.descriptor }.toSet())
            val conflicting = calls.filter { it.rpc == "Conflicting" }
            assertEquals(2, conflicting.size)
            assertEquals(setOf(raw(version, "ConflictFirstRequest"), raw(version, "ConflictSecondRequest")),
                conflicting.flatMap { it.requestTypes }.map { it.descriptor }.toSet())
            val expectedOwners = (accepted.keys + unreviewed + ambiguous + unknown).map { raw(version, it) }.toSet()
            assertEquals(expectedOwners, discovery.leads.map { it.owner.descriptor }.toSet(), "Independent source classes define discovery truth")
            assertEquals(discovery.leads.size, discovery.leads.map { it.owner }.distinct().size, "Shared RPC roles have one entity lead")
            val shared = discovery.leads.single { it.owner.descriptor == raw(version, "SharedRecord") }
            assertNull(shared.suggestedName, "Conflicting RPC role suggestions cannot choose an arbitrary class name")
            val rules = discoveryDir.resolve("rules.json")
            generated[version] = rules
            val drafts = cli.read<AnalysisRuleFile>(rules)
            assertEquals(expectedOwners.size, drafts.items.size)
            assertTrue(drafts.items.all { it.strategy?.strategyId == "grpc-java.rpc-message" })
            val sharedRule = drafts.items.single { it.discoveryKey == shared.key }.strategy!!
            assertEquals(3, sharedRule.parameters.getAsJsonArray("selectors").size(), "Send request/response and Report request share one class")
            assertTrue(drafts.items.any { item -> item.strategy!!.parameters.getAsJsonArray("selectors").any {
                it.asJsonObject["service"].asString == "fixture.theme.Outside"
            } }, "The review-service scope cannot narrow full-APK matching or discovery")

            val dir = cli.output.resolve("$version-run")
            cli.execute("$version-prepare", "analysis", "prepare", "--apk", apk(version), "--rules", rules,
                "--base-knowledge", knowledge(base), "--reference-knowledge", knowledge(references.getValue(version)), "--run", dir)
            val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
            val taskByClass = expectedOwners.associateWith { owner -> run.tasks.single { it.expectedOwner?.descriptor == owner } }
            (accepted.keys + unreviewed).forEach { name -> assertUnique(taskByClass.getValue(raw(version, name)).resolution!!, version, name) }
            ambiguous.forEach { name -> assertEquals(ResolutionStatus.AMBIGUOUS, taskByClass.getValue(raw(version, name)).resolution!!.status) }
            unknown.forEach { name ->
                val proof = taskByClass.getValue(raw(version, name)).resolution!!
                assertEquals(ResolutionStatus.UNKNOWN, proof.status)
                assertTrue(proof.unresolvedPaths.orEmpty().isNotEmpty(), "An unresolved possible construction must remain visible")
            }
            val referenced = taskByClass.getValue(raw(version, "GroupRequest"))
            val referenceEntry = cli.read<VersionKnowledge>(knowledge(references.getValue(version))).entries.single()
            assertEquals(referenceEntry.semanticId, referenced.semanticId)
            assertEquals(referenceEntry.name, referenced.existingEntry?.name)
            val noReview = cli.output.resolve("$version-no-review")
            cli.execute("$version-publish-without-review", "analysis", "publish", "--run", dir, "--out", noReview)
            assertTrue(cli.read<VersionKnowledge>(knowledge(noReview)).entries.isEmpty(), "Reference knowledge cannot supply new semantic review")

            val page = cli.result<AnalysisTaskPage>("$version-group-queue", "analysis", "tasks", "--run", dir,
                "--service", "fixture.theme.Group", "--limit", 100)
            assertTrue(page.items.isNotEmpty())
            assertTrue(page.items.all { view -> view.task.rule.parameters.getAsJsonArray("selectors").any {
                it.asJsonObject["service"].asString == "fixture.theme.Group"
            } })
            val selected = accepted.map { (name, alias) -> taskByClass.getValue(raw(version, name)) to alias }
            val evidence = inspect("analysis", dir, selected.map { it.first.taskId })
            val reviews = selected.map { (task, alias) -> analysisReview(task, alias, evidence) }
            val badName = reviews.single { it.taskId == referenced.taskId }.copy(name = "CannotReplaceCanonicalIdentity")
            submitAnalysis("$version-reference-name-rejected", dir, run, listOf(badName), expectedExit = 2)
            val invalid = taskByClass.getValue(raw(version, "UnknownRequest"))
            submitAnalysis("$version-unknown-cannot-accept", dir, run, listOf(analysisReview(invalid, "MustNotPublish", evidence)), expectedExit = 2)
            submitAnalysis("$version-submit", dir, run, reviews)
            val out = cli.output.resolve("$version-published")
            cli.execute("$version-publish", "analysis", "publish", "--run", dir, "--out", out)
            verifyPublished(out, version)
            published[version] = out
            val replay = cli.output.resolve("$version-replay")
            cli.execute("$version-replay", "analysis", "publish", "--run", dir, "--out", replay, "--at", out.resolve("report.json"))
            assertEquals(Files.readString(knowledge(out)), Files.readString(knowledge(replay)))
            assertEquals(Files.readString(out.resolve("mapping.tiny")), Files.readString(replay.resolve("mapping.tiny")))
            PublishedFixtureAssertions.verify(cli, apk(version), knowledge(replay), oracle.getValue(version),
                accepted.entries.associate { it.value to namespace + it.key }, anchorTruth(version))
        }
        val source = cli.read<VersionKnowledge>(knowledge(published.getValue("v1")))
        val target = cli.read<VersionKnowledge>(knowledge(published.getValue("v2")))
        accepted.values.forEach { alias ->
            val old = source.entries.single { it.name == alias }
            val current = target.entries.single { it.name == alias }
            assertEquals(old.ruleRevision, current.ruleRevision, "Same selectors must be replayed across actual R8 symbols")
            assertNotEquals(old.binding.descriptor, current.binding.descriptor)
            assertNotEquals(old.resolution!!.resolutionId, current.resolution!!.resolutionId)
        }
        assertEquals(source.entries.single { it.name == "CanonicalGroupRequest" }.semanticId,
            target.entries.single { it.name == "CanonicalGroupRequest" }.semanticId)
        rejectReferences(references, bases.getValue("v2"), generated.getValue("v2"))
        checkNonConstruction(bases.getValue("v2"))
        cli.write("summary.json", mapOf("schemaVersion" to 1, "status" to "PASS", "publishedPerVersion" to accepted.size,
            "reviewServices" to services, "commands" to cli.commandCount, "timings" to cli.timingSummary))
    }

    private fun seedAnchors(version: String): Path {
        val anchors = listOf("rpc" to "Group", "ambiguous" to "Ambiguous").flatMap { (key, service) -> listOf(
            AnalysisAnchorDefinition("$key.seed", strategy = StrategySpec("messages.rpc-descriptor",
                parameters("service" to "fixture.theme.$service", "rpc" to "Seed"), EntityKind.METHOD)),
            AnalysisAnchorDefinition("$key.descriptor", strategy = StrategySpec("messages.rpc-related-type",
                parameters("role" to "descriptor"), requires = mapOf("descriptor" to "$key.seed"))),
            AnalysisAnchorDefinition("$key.full-name", strategy = StrategySpec("grpc-java.full-method-name",
                resultKind = EntityKind.METHOD, requires = mapOf("descriptor" to "$key.descriptor")))) }
        val rules = cli.write("inputs/$version-anchors.json", AnalysisRuleFile(anchors = anchors))
        var base: Path? = null
        for (round in 1..3) {
            val dir = cli.output.resolve("$version-anchor-run-$round")
            val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk(version), "--rules", rules, "--run", dir)
            base?.let { args.addAll(listOf("--base-knowledge", knowledge(it))) }
            cli.execute("$version-anchor-$round", *args.toTypedArray())
            val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
            if (round == 3) {
                val unique = run.anchorTasks.single { it.key == "rpc.full-name" }.resolution!!
                assertEquals(ResolutionStatus.UNIQUE, unique.status)
                assertMethod(unique.uniqueMethod!!, version, "ThemeDescriptor", "name", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
                val multiple = run.anchorTasks.single { it.key == "ambiguous.full-name" }.resolution!!
                assertEquals(ResolutionStatus.AMBIGUOUS, multiple.status)
                val expected = listOf("name", "alternate").map { oracle.getValue(version).method(namespace + "AmbiguousDescriptor", it,
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;") }.toSet()
                assertEquals(expected.map { it.owner }.toSet(), setOf(raw(version, "AmbiguousDescriptor")))
                assertEquals(expected.map { it.name + it.descriptor }.toSet(), multiple.candidates.map { it.method!!.name + it.method!!.descriptor }.toSet())
            }
            val out = cli.output.resolve("$version-anchor-published-$round")
            cli.execute("$version-anchor-publish-$round", "analysis", "publish", "--run", dir, "--out", out)
            val packageValue = cli.read<VersionKnowledge>(knowledge(out))
            assertTrue(packageValue.entries.isEmpty())
            assertEquals(if (round == 1) 2 else if (round == 2) 4 else 5, packageValue.anchors.size)
            PublishedFixtureAssertions.verify(cli, apk(version), knowledge(out), oracle.getValue(version), emptyMap(), anchorTruth(version))
            base = out
        }
        return base!!
    }

    private fun canonicalReferences(): Map<String, Path> {
        val source = publishMarker("reference-source", "v1", "CanonicalGroupRequest")
        val dir = cli.output.resolve("reference-migration")
        cli.execute("reference-migration-prepare", "migration", "prepare", "--knowledge", knowledge(source), "--source-apk", apk("v1"),
            "--target-apk", apk("v2"), "--run", dir)
        val run = cli.read<MigrationRun>(dir.resolve("run.json"))
        val task = run.tasks.single()
        assertUnique(task.resolution!!, "v2", "GroupRequest")
        val evidence = inspect("migration", dir, listOf(task.taskId))
        val review = cli.write("reviews/reference-migration.json", MigrationReviewBatch(runId = run.runId,
            sourceKnowledgeId = run.knowledge.knowledgeId, sourceApkSha256 = run.sourceApk.sha256, targetApkSha256 = run.targetApk.sha256,
            items = listOf(MigrationReview(task.taskId, task.resolution!!.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT,
                Confidence.HIGH, true, "The source-authored request keeps its role in both fixture versions.",
                listOf("R8 changes the original descriptor."), listOf("Static fixture truth only."), evidence.map { it.evidenceId }))))
        cli.execute("reference-migration-submit", "migration", "submit", "--run", dir, "--review", review)
        val target = cli.output.resolve("reference-target")
        cli.execute("reference-migration-publish", "migration", "publish", "--run", dir, "--out", target)
        PublishedFixtureAssertions.verify(cli, apk("v2"), knowledge(target), oracle.getValue("v2"), mapOf("CanonicalGroupRequest" to namespace + "GroupRequest"))
        assertEquals(cli.read<VersionKnowledge>(knowledge(source)).entries.single().semanticId,
            cli.read<VersionKnowledge>(knowledge(target)).entries.single().semanticId)
        return mapOf("v1" to source, "v2" to target)
    }

    private fun publishMarker(label: String, version: String, alias: String): Path {
        val rules = cli.write("inputs/$label.json", AnalysisRuleFile(items = listOf(AnalysisRuleItem("canonical", proposedName = alias,
            locators = listOf(Locator("string-use", "theme-canonical-request"))))))
        val dir = cli.output.resolve("$label-run")
        cli.execute("$label-prepare", "analysis", "prepare", "--apk", apk(version), "--rules", rules, "--run", dir)
        val run = cli.read<AnalysisRun>(dir.resolve("run.json"))
        val task = run.tasks.single()
        assertUnique(task.resolution!!, version, "GroupRequest")
        val evidence = inspect("analysis", dir, listOf(task.taskId))
        submitAnalysis("$label-submit", dir, run, listOf(analysisReview(task, alias, evidence)))
        val out = cli.output.resolve("$label-published")
        cli.execute("$label-publish", "analysis", "publish", "--run", dir, "--out", out)
        PublishedFixtureAssertions.verify(cli, apk(version), knowledge(out), oracle.getValue(version), mapOf(alias to namespace + "GroupRequest"))
        return out
    }

    private fun rejectReferences(references: Map<String, Path>, base: Path, rules: Path) {
        cli.execute("reference-wrong-apk", "analysis", "prepare", "--apk", apk("v2"), "--rules", rules,
            "--base-knowledge", knowledge(base), "--reference-knowledge", knowledge(references.getValue("v1")),
            "--run", cli.output.resolve("wrong-apk-reference"), expectedExit = 2)
        val conflicting = publishMarker("conflicting-current-identity", "v2", "ConflictingGroupRequest")
        val first = cli.read<VersionKnowledge>(knowledge(references.getValue("v2"))).entries.single()
        val second = cli.read<VersionKnowledge>(knowledge(conflicting)).entries.single()
        assertEquals(first.binding, second.binding)
        assertNotEquals(first.semanticId, second.semanticId, "The reference holds a migrated identity while this isolated analysis creates a current-APK identity")
        cli.execute("reference-conflict", "analysis", "prepare", "--apk", apk("v2"), "--rules", rules,
            "--base-knowledge", knowledge(base), "--reference-knowledge", knowledge(references.getValue("v2")),
            "--reference-knowledge", knowledge(conflicting), "--run", cli.output.resolve("conflicting-reference"), expectedExit = 2)
    }

    private fun checkNonConstruction(base: Path) {
        val rules = cli.write("inputs/non-construction.json", AnalysisRuleFile(items =
            listOf("configuration-only" to "ConfigurationOnly", "escaped-name" to "EscapedName", "opaque-helper" to "OpaqueHelper").map { (key, rpc) ->
                AnalysisRuleItem(key, proposedName = "NotAProto", strategy = StrategySpec("grpc-java.rpc-message",
                    parameters("selectors" to listOf(mapOf("service" to "fixture.theme.Group", "rpc" to rpc, "role" to "request"))),
                    requires = mapOf("nameFactory" to "rpc.full-name")))
            }))
        val dir = cli.output.resolve("configuration-only-run")
        cli.execute("non-construction-prepare", "analysis", "prepare", "--apk", apk("v2"), "--rules", rules,
            "--base-knowledge", knowledge(base), "--run", dir)
        val tasks = cli.read<AnalysisRun>(dir.resolve("run.json")).tasks
        assertEquals(ResolutionStatus.NO_MATCH, tasks.single { it.taskId == "configuration-only" }.resolution!!.status)
        for (id in listOf("escaped-name", "opaque-helper")) {
            val unresolved = tasks.single { it.taskId == id }.resolution!!
            assertEquals(ResolutionStatus.UNKNOWN, unresolved.status)
            assertTrue(unresolved.candidates.isEmpty(), "UNKNOWN without a recoverable type must not fabricate an owner candidate")
            assertTrue(unresolved.unresolvedPaths.orEmpty().isNotEmpty())
        }
    }

    private fun anchorTruth(version: String) = mapOf(
        "rpc.seed" to ExpectedPublishedAnchor(namespace + "ThemeRpcCases", "seed", if (version == "v1") "()${type("ThemeDescriptor")}" else "()Ljava/lang/Object;"),
        "rpc.descriptor" to ExpectedPublishedAnchor(namespace + "ThemeDescriptor"),
        "rpc.full-name" to ExpectedPublishedAnchor(namespace + "ThemeDescriptor", "name", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
        "ambiguous.seed" to ExpectedPublishedAnchor(namespace + "ThemeRpcCases", "ambiguousSeed", "()Ljava/lang/Object;"),
        "ambiguous.descriptor" to ExpectedPublishedAnchor(namespace + "AmbiguousDescriptor"))

    private fun verifyPublished(out: Path, version: String) {
        val facts = PublishedFixtureAssertions.verify(cli, apk(version), knowledge(out), oracle.getValue(version),
            accepted.entries.associate { it.value to namespace + it.key }, anchorTruth(version))
        assertEquals(accepted.size, facts.entries.size)
        assertEquals(accepted.values.toSet(), facts.entries.map { it.name }.toSet())
        val mapping = Files.readAllLines(out.resolve("mapping.tiny"))
        assertEquals(accepted.size + 1, mapping.size)
        assertTrue(mapping.drop(1).all { it.startsWith("c\t") })
        val shown = cli.result<Array<VerifiedRename>>("${out.fileName}-readback", "knowledge", "verify", "--knowledge", knowledge(out),
            "--apk", apk(version), "--work", out.resolve("readback"))
        assertEquals(facts.entries.map { it.clazz.descriptor }.toSet(), shown.map { it.descriptor }.toSet())
    }
    private fun assertUnique(resolution: Resolution, version: String, sourceName: String) {
        assertEquals(ResolutionStatus.UNIQUE, resolution.status)
        assertEquals(raw(version, sourceName), resolution.uniqueRef!!.descriptor)
    }
    private fun assertMethod(ref: MethodRef, version: String, owner: String, name: String, descriptor: String) {
        val expected = oracle.getValue(version).method(namespace + owner, name, descriptor)
        assertEquals(expected.owner, ref.owner.descriptor)
        assertEquals(expected.name, ref.name)
        assertEquals(expected.descriptor, ref.descriptor)
    }
    private fun inspect(scene: String, dir: Path, tasks: List<String>) = cli.result<Array<EvidenceRecord>>("${dir.fileName}-inspect",
        scene, "inspect", "--run", dir, "--task", tasks.joinToString(",")).toList()
    private fun analysisReview(task: AnalysisTask, alias: String, evidence: List<EvidenceRecord>): AnalysisReview {
        val proof = task.resolution!!
        val refs = buildSet {
            proof.uniqueRef?.let(::add)
            proof.matches.filter { it.status == MatchStatus.PASS && it.owner == proof.uniqueRef }.forEach {
                addAll(it.relatedRefs)
                addAll(it.trace.map { trace -> trace.owner })
            }
            proof.dependencies.values.forEach {
                add(it.binding.owner)
                addAll(KnowledgeFiles.evidenceClosure(it).map { e -> e.ref })
            }
        }
        assertTrue(refs.all { ref -> evidence.any { it.ref == ref } }, "Batch inspection must retain this task's complete supporting evidence")
        return AnalysisReview(task.taskId, proof.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT, alias, Confidence.HIGH,
            "Self-authored $alias role checked against independent R8 identity and current descriptor evidence.",
            listOf("Static integration truth; no model judgment or remote RPC behavior is measured."),
            evidence.filter { it.ref in refs }.map { it.evidenceId })
    }
    private fun submitAnalysis(label: String, dir: Path, run: AnalysisRun, reviews: List<AnalysisReview>, expectedExit: Int = 0) {
        val file = cli.write("reviews/$label.json", AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256, items = reviews))
        cli.execute(label, "analysis", "submit", "--run", dir, "--review", file, expectedExit = expectedExit)
    }
}
