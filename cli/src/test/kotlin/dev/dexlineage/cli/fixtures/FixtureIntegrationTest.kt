package dev.dexlineage.cli.fixtures

import dev.dexlineage.analysis.*
import dev.dexlineage.migration.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.test.*

/**
 * Protocol integration, not an evaluation of Agent judgement. Semantic conclusions are authored
 * with the fixture source. Only execution IDs and evidence references are filled from CLI output.
 * The independent R8 oracle is never passed to the CLI, even during inspect.
 */
@Tag("fixture-integration")
class FixtureIntegrationTest {
    private lateinit var cli: FixtureCli
    private lateinit var manifest: FixtureManifest
    private lateinit var repo: Path
    private lateinit var oracles: Map<String, R8Oracle>
    private val results = linkedMapOf<String, Any>()

    @Test
    fun `R8 APKs exercise the installed CLI from discovery through durable knowledge and mapping readback`() {
        val fixtureRoot = requiredPath("dexlineage.fixtureRoot")
        val casePath = requiredPath("dexlineage.fixtureCases")
        repo = fixtureRoot.parent.parent
        val output = requiredPath("dexlineage.fixtureResults").resolve("run-${UUID.randomUUID()}")
        cli = FixtureCli(requiredPath("dexlineage.distributionDir"), output, repo)
        manifest = FixtureManifest.read(casePath)
        FixturePreflight.verify(fixtureRoot, casePath, output.resolve("preflight"))
        oracles = manifest.versions.mapValues { (_, v) -> R8Oracle(repo.resolve(v.mapping)) }

        // Execute every declared regression in both real APKs, including cases discovery cannot draft.
        for (version in listOf("v1", "v2")) {
            val definitions = cli.write("inputs/all-$version.json", AnalysisRuleFile(items = manifest.cases.map { scenario ->
                AnalysisRuleItem(scenario.id, proposedName = scenario.semanticAlias, locators = listOf(locator(scenario.component)))
            }))
            val dir = output.resolve("all-$version")
            val run = prepareAnalysis(version, definitions, dir)
            assertEquals(manifest.cases.map { it.id }.toSet(), run.tasks.map { it.taskId }.toSet())
            run.tasks.forEach { task -> assertResolution(task.resolution, scenario(task.taskId), version) }
            val unknown = run.tasks.single { it.taskId == "unknownCompetitor" }.resolution
            assertEquals(setOf(MatchStatus.PASS, MatchStatus.UNKNOWN), unknown.candidates.map { it.status }.toSet())
            results["$version-all-rules"] = run.tasks.associate { it.taskId to it.resolution.status }
            if (version == "v1") verifyUnknownAndMissingEvidence(dir, run)
            val empty = publish("analysis", dir, output.resolve("all-$version-unreviewed"))
            assertTrue(empty.entries.isEmpty(), "A UNIQUE match without review must not publish")
        }

        val profile = cli.write("inputs/log-fields.json", profile(manifest.versions.getValue("v1").tag))
        val discoverDir = output.resolve("discovery")
        cli.execute("discover", "analysis", "discover", "--apk", apk("v1"), "--profile", profile, "--out", discoverDir)
        val discovery = cli.read<AnalysisDiscovery>(discoverDir.resolve("discovery.json"))
        val expectedOwners = manifest.cases.flatMap { it.versions.getValue("v1").discoveryOwners }
            .map(oracles.getValue("v1")::descriptor).toSet()
        assertEquals(expectedOwners, discovery.leads.map { it.owner.descriptor }.toSet(), "Scope discovery uses real structure")
        val sourceDir = output.resolve("analysis-source")
        val sourceRun = prepareAnalysis("v1", discoverDir.resolve("rules.json"), sourceDir)
        sourceRun.tasks.forEach { assertResolution(it.resolution, caseFor(it), "v1") }
        // The external-scope owner must be present even though it was not a discovery lead.
        val collision = sourceRun.tasks.single { caseFor(it).id == "outsideScopeCollision" }
        assertEquals(2, collision.resolution.candidates.size)
        assertEquals(1, scenario("outsideScopeCollision").versions.getValue("v1").discoveryOwners.size)

        val sourceEvidence = inspectAnalysis(sourceDir, sourceRun)
        val sourceReviews = sourceRun.tasks.filter { it.resolution.status == ResolutionStatus.UNIQUE }
            .map { analysisReview(sourceRun, it, sourceEvidence, "v1", caseFor(it).semanticAlias) }
        assertEquals(manifest.cases.filter { it.versions.getValue("v1").resolution == "UNIQUE" }.map { it.semanticAlias }.toSet(),
            sourceReviews.map { it.name }.toSet())
        val before = analysisPage(sourceDir)
        assertEquals(sourceRun.tasks.size, before.total)
        assertTrue(before.items.all { it.state == if (it.task.resolution.status == ResolutionStatus.UNIQUE) TaskState.UNREVIEWED else TaskState.INVALID })
        val invalid = sourceRun.tasks.first { caseFor(it).id == "alwaysAmbiguous" }
        rejectAnalysis(sourceDir, sourceRun, listOf(AnalysisReview(invalid.taskId, invalid.resolution.resolutionId,
            invalid.rule.revisionId, ReviewAction.ACCEPT, "DifferentAliasCannotChooseAnOwner", Confidence.HIGH,
            "Deliberately invalid: semantic confidence cannot remove the second owner.")), "ambiguous-high-alias")
        rejectAnalysis(sourceDir, sourceRun, listOf(sourceReviews.first().copy(resolutionId = "wrong-resolution")), "wrong-resolution")
        rejectAnalysis(sourceDir, sourceRun, listOf(sourceReviews.first().copy(ruleRevisionId = "wrong-rule")), "wrong-rule")
        val foreign = sourceEvidence.first { record -> record.ref.descriptor == sourceRun.tasks
            .single { it.taskId == sourceReviews[1].taskId }.resolution.uniqueRef!!.descriptor }
        rejectAnalysis(sourceDir, sourceRun, listOf(sourceReviews.first().copy(evidenceIds = listOf(foreign.evidenceId))), "foreign-evidence")
        rejectAnalysis(sourceDir, sourceRun, listOf(sourceReviews.first(), sourceReviews[1].copy(resolutionId = "wrong-resolution")), "atomic-invalid-batch")
        val obsolete = cli.gson.toJsonTree(analysisBatch(sourceRun, listOf(sourceReviews.first()))).asJsonObject
        obsolete.getAsJsonArray("items")[0].asJsonObject.addProperty("targetDescriptor", sourceRun.tasks
            .single { it.taskId == sourceReviews.first().taskId }.resolution.uniqueRef!!.descriptor)
        val obsoletePath = cli.write("reviews/obsolete-analysis-selection.json", obsolete)
        cli.execute("obsolete-analysis-selection", "analysis", "submit", "--run", sourceDir, "--review", obsoletePath, expectedExit = 2)
        assertEquals(before, analysisPage(sourceDir), "Rejected batch must not partially commit a review")

        val noReviewDir = output.resolve("source-without-review")
        assertTrue(publish("analysis", sourceDir, noReviewDir).entries.isEmpty())
        val reviewPath = cli.write("reviews/source.json", analysisBatch(sourceRun, sourceReviews))
        val submitted = cli.result<AnalysisSubmitResult>("source-submit", "analysis", "submit", "--run", sourceDir, "--review", reviewPath)
        val repeated = cli.result<AnalysisSubmitResult>("source-retry", "analysis", "submit", "--run", sourceDir, "--review", reviewPath)
        assertEquals(submitted, repeated, "Identical submissions are idempotent across processes")
        val after = analysisPage(sourceDir)
        assertEquals(sourceReviews.size, after.items.count { it.state == TaskState.ACCEPTED })
        val page = cli.result<AnalysisTaskPage>("queue-page", "analysis", "tasks", "--run", sourceDir, "--state", "ALL", "--offset", 1, "--limit", 2)
        assertEquals(after.items.drop(1).take(2), page.items)

        val sourceOut = output.resolve("source-published")
        val sourceKnowledge = publish("analysis", sourceDir, sourceOut)
        val sourceExpected = manifest.cases.filter { it.versions.getValue("v1").resolution == "UNIQUE" }
            .associate { oracles.getValue("v1").descriptor(it.versions.getValue("v1").owners.single()) to it.semanticAlias }
        assertKnowledge(sourceKnowledge, sourceExpected)
        assertTrue(sourceKnowledge.unresolved.isEmpty(), "Unconfirmed Analysis proposals are not prior knowledge")
        val privateEntry = sourceKnowledge.entries.single { it.name == scenario("privateCache").semanticAlias }
        assertEquals(scenario("privateCache").component, privateEntry.captures["component"])
        assertNotEquals(privateEntry.name, privateEntry.captures["component"], "Confirmed alias and locator capture have different roles")
        assertTrue(privateEntry.locators.all { it.anchor == scenario("privateCache").component })
        assertMappingAndVerify(sourceOut, "v1", sourceExpected)
        verifyAnalysisHistory(sourceDir, sourceRun, sourceReviews, submitted, sourceOut)

        val migrationDir = output.resolve("migration")
        val migration = prepareMigration(sourceOut, migrationDir)
        assertEquals(sourceKnowledge.entries.map { it.semanticId }.toSet(), migration.tasks.map { it.entry.semanticId }.toSet())
        migration.tasks.forEach { assertResolution(it.resolution, caseFor(it), "v2") }
        assertEquals(sourceKnowledge, migration.knowledge, "The exact published knowledge file is the handoff")
        val migrationEvidence = inspectMigration(migrationDir, migration)
        val migrationReviews = migration.tasks.filter { it.resolution.status == ResolutionStatus.UNIQUE }
            .map { migrationReview(migration, it, migrationEvidence) }
        val absentReview = publish("migration", migrationDir, output.resolve("migration-without-review"))
        assertTrue(absentReview.entries.isEmpty())
        assertEquals(sourceKnowledge.entries.size, absentReview.unresolved.size)
        rejectMigrationSelections(migrationDir, migration, migrationReviews)
        val migrationReviewPath = cli.write("reviews/migration.json", migrationBatch(migration, migrationReviews))
        val migrationSubmit = cli.execute("migration-submit", "migration", "submit", "--run", migrationDir, "--review", migrationReviewPath)
        assertEquals(migrationSubmit, cli.execute("migration-idempotent", "migration", "submit", "--run", migrationDir, "--review", migrationReviewPath))
        val migrationTasks = cli.result<MigrationTasksPage>("migration-resume", "migration", "tasks", "--run", migrationDir, "--state", "ALL", "--limit", 100)
        assertEquals(migrationReviews.size, migrationTasks.tasks.count { it.state == TaskState.ACCEPTED })
        val migratedOut = output.resolve("migration-published")
        val migrated = publish("migration", migrationDir, migratedOut)
        val migrationExpected = sourceExpected.values.map { name -> manifest.cases.single { it.semanticAlias == name } }
            .filter { it.versions.getValue("v2").resolution == "UNIQUE" }
            .associate { oracles.getValue("v2").descriptor(it.versions.getValue("v2").owners.single()) to it.semanticAlias }
        assertKnowledge(migrated, migrationExpected)
        assertUnresolved(migrated, sourceKnowledge, setOf("removedSignal", "becomesAmbiguous"))
        assertMappingAndVerify(migratedOut, "v2", migrationExpected)
        replay("migration", migrationDir, migratedOut, output.resolve("migration-replay"))

        val replacedOut = verifyRuleReplacement(sourceOut, sourceKnowledge, migration)
        val replaced = cli.read<VersionKnowledge>(replacedOut.resolve("knowledge.json"))
        val finalOut = verifySameApkUpdates(replacedOut, replaced)
        val finalKnowledge = cli.read<VersionKnowledge>(finalOut.resolve("knowledge.json"))
        val finalExpected = migrationExpected.toMutableMap().apply {
            val changing = scenario("becomesAmbiguous")
            put(oracles.getValue("v2").descriptor(changing.versions.getValue("v1").owners.single()), changing.semanticAlias)
            put(oracles.getValue("v2").descriptor(scenario("privateCache").versions.getValue("v2").owners.single()), "RefinedPrivateCache")
        }
        assertKnowledge(finalKnowledge, finalExpected)
        assertMappingAndVerify(finalOut, "v2", finalExpected)
        results["sourceConfirmed"] = sourceKnowledge.entries.size
        results["migrationConfirmed"] = migrated.entries.size
        results["migrationUnresolved"] = migrated.unresolved.size
        results["finalConfirmed"] = finalKnowledge.entries.size
        results["finalUnresolved"] = finalKnowledge.unresolved.size
        results["commands"] = cli.commandCount
        results["reviewMeaning"] = "Source-authored fixture truth, not an Agent judgement evaluation"
        cli.write("summary.json", results)
    }

    private fun verifyUnknownAndMissingEvidence(dir: Path, run: AnalysisRun) {
        val unknown = run.tasks.single { it.taskId == "unknownCompetitor" }
        rejectAnalysis(dir, run, listOf(AnalysisReview(unknown.taskId, unknown.resolution.resolutionId,
            unknown.rule.revisionId, ReviewAction.ACCEPT, "CannotIgnoreUnknownCompetitor", Confidence.HIGH,
            "Deliberately invalid: an unresolved competing entity prevents unique identification.")), "unknown-high-accept")
        val task = run.tasks.single { it.taskId == "publicCache" }
        val evidence = cli.result<Array<EvidenceRecord>>("owner-evidence-inspect", "analysis", "inspect", "--run", dir, "--task", task.taskId).toList()
        checkEvidence(dir, evidence)
        val complete = analysisReview(run, task, evidence, "v1", scenario("publicCache").semanticAlias)
        val owner = oracles.getValue("v1").descriptor(scenario("publicCache").versions.getValue("v1").owners.single())
        val ownerOnly = complete.copy(evidenceIds = listOf(evidence.single { it.ref.descriptor == owner }.evidenceId))
        val file = cli.write("reviews/missing-factory-evidence.json", analysisBatch(run, listOf(ownerOnly)))
        cli.execute("missing-factory-evidence-submit", "analysis", "submit", "--run", dir, "--review", file)
        val deferred = analysisPage(dir).items.single { it.task.taskId == task.taskId }
        assertEquals(TaskState.DEFERRED, deferred.state)
        assertEquals("owner_or_factory_evidence_missing", deferred.reason)
    }

    private fun verifyAnalysisHistory(dir: Path, run: AnalysisRun, reviews: List<AnalysisReview>, submitted: AnalysisSubmitResult, firstOut: Path) {
        val changed = reviews.first().copy(action = ReviewAction.DEFER, rationale = "Fixture revision deliberately defers the previously accepted proposal.")
        rejectAnalysis(dir, run, listOf(changed), "requires-explicit-supersedes")
        val replacement = changed.copy(supersedes = submitted.revisions.getValue(changed.taskId))
        val file = cli.write("reviews/source-revision.json", analysisBatch(run, listOf(replacement)))
        cli.execute("source-revision", "analysis", "submit", "--run", dir, "--review", file)
        val later = publish("analysis", dir, cli.output.resolve("source-later"))
        assertEquals(reviews.size - 1, later.entries.size)
        val page = analysisPage(dir)
        assertEquals(run.tasks.size, page.total)
        assertEquals(TaskState.DEFERRED, page.items.single { it.task.taskId == changed.taskId }.state)
        replay("analysis", dir, firstOut, cli.output.resolve("source-historical-replay"))
    }

    private fun verifyRuleReplacement(sourceOut: Path, source: VersionKnowledge, original: MigrationRun): Path {
        val changed = source.entries.single { it.name == scenario("becomesAmbiguous").semanticAlias }
        val specific = locator(scenario("becomesAmbiguous").component, manifest.versions.getValue("v2").tag)
        val orFile = cli.write("inputs/migration-or.json", MigrationRulesFile(items = listOf(
            MigrationRuleOverride(changed.semanticId, changed.locators + specific, changed.ruleRevision!!.revisionId))))
        val orRun = prepareMigration(sourceOut, cli.output.resolve("migration-or"), orFile)
        assertResolution(orRun.tasks.single { it.entry.semanticId == changed.semanticId }.resolution, scenario("becomesAmbiguous"), "v2")
        val override = cli.write("inputs/migration-replacement.json", MigrationRulesFile(items = listOf(
            MigrationRuleOverride(changed.semanticId, listOf(specific), changed.ruleRevision!!.revisionId))))
        val dir = cli.output.resolve("migration-replacement")
        val run = prepareMigration(sourceOut, dir, override)
        assertEquals(source.entries.map { it.semanticId }.toSet(), run.tasks.map { it.entry.semanticId }.toSet())
        val task = run.tasks.single { it.entry.semanticId == changed.semanticId }
        val expected = oracles.getValue("v2").descriptor(scenario("becomesAmbiguous").versions.getValue("v1").owners.single())
        assertEquals(ResolutionStatus.UNIQUE, task.resolution.status)
        assertEquals(setOf(expected), task.resolution.candidates.map { it.ref.descriptor }.toSet())
        assertEquals(listOf(specific), task.resolution.rule.locators)
        assertNotEquals(changed.ruleRevision!!.revisionId, task.resolution.rule.revisionId)
        run.tasks.filter { it.entry.semanticId != changed.semanticId }.forEach { assertResolution(it.resolution, caseFor(it), "v2") }
        val evidence = inspectMigration(dir, run)
        val reviews = run.tasks.filter { it.resolution.status == ResolutionStatus.UNIQUE }.map { migrationReview(run, it, evidence) }
        val stale = reviews.single { it.taskId == task.taskId }.copy(resolutionId = original.tasks
            .single { it.entry.semanticId == changed.semanticId }.resolution.resolutionId)
        val staleFile = cli.write("reviews/stale-migration-proof.json", migrationBatch(run, listOf(stale)))
        cli.execute("old-resolution-after-rule-replacement", "migration", "submit", "--run", dir, "--review", staleFile, expectedExit = 2)
        val path = cli.write("reviews/replacement.json", migrationBatch(run, reviews))
        cli.execute("replacement-submit", "migration", "submit", "--run", dir, "--review", path)
        val out = cli.output.resolve("replacement-published")
        val knowledge = publish("migration", dir, out)
        assertEquals(source.entries.size - 1, knowledge.entries.size)
        assertEquals(listOf(specific), knowledge.entries.single { it.semanticId == changed.semanticId }.locators)
        assertUnresolved(knowledge, source, setOf("removedSignal"))
        return out
    }

    private fun verifySameApkUpdates(baseOut: Path, base: VersionKnowledge): Path {
        val old = base.entries.single { it.name == scenario("privateCache").semanticAlias }
        val strict = locator(scenario("privateCache").component).let { locator ->
            locator.copy(factors = locator.factors.map { if (it.kind == "field-flags") it.copy(visibility = "PRIVATE") else it })
        }
        val rules = cli.write("inputs/current-update.json", AnalysisRuleFile(items = listOf(
            AnalysisRuleItem("private-update", proposedName = "RefinedPrivateCache", locators = listOf(strict)))))
        val dir = cli.output.resolve("analysis-update")
        val run = prepareAnalysis("v2", rules, dir, baseOut.resolve("knowledge.json"))
        val task = run.tasks.single()
        assertResolution(task.resolution, scenario("privateCache"), "v2")
        assertEquals(old.semanticId, task.semanticId, "Current raw identity, rather than an alias, must reuse semanticId")
        val evidence = inspectAnalysis(dir, run)
        val review = analysisReview(run, task, evidence, "v2", "RefinedPrivateCache", scenario("privateCache"))
        val reviewFile = cli.write("reviews/current-update.json", analysisBatch(run, listOf(review)))
        cli.execute("update-submit", "analysis", "submit", "--run", dir, "--review", reviewFile)
        val out = cli.output.resolve("current-published")
        val current = publish("analysis", dir, out)
        assertEquals(base.knowledgeId, current.parentKnowledgeId)
        assertEquals(base.entries.map { it.semanticId }.toSet(), current.entries.map { it.semanticId }.toSet())
        assertEquals(base.entries.filter { it.semanticId != old.semanticId }, current.entries.filter { it.semanticId != old.semanticId })
        assertEquals(base.unresolved, current.unresolved)
        val updated = current.entries.single { it.semanticId == old.semanticId }
        assertEquals("RefinedPrivateCache", updated.name)
        assertEquals(listOf(strict), updated.locators)
        assertEquals(old.binding, updated.binding)

        val failingRules = cli.write("inputs/failed-update.json", AnalysisRuleFile(items = listOf(
            AnalysisRuleItem("failed-update", semanticId = old.semanticId, proposedName = "MustNotReplaceExistingName",
                locators = listOf(locator("AbsentFixtureLiteral"))))))
        val failDir = cli.output.resolve("analysis-failed-update")
        val failed = prepareAnalysis("v2", failingRules, failDir, out.resolve("knowledge.json"))
        assertEquals(ResolutionStatus.NO_MATCH, failed.tasks.single().resolution.status)
        val failedOut = cli.output.resolve("failed-update-published")
        val preserved = publish("analysis", failDir, failedOut)
        assertEquals(current.entries, preserved.entries, "Failed rule attempts cannot overwrite valid knowledge")
        assertEquals(current.unresolved, preserved.unresolved)
        assertEquals(Files.readString(out.resolve("mapping.tiny")), Files.readString(failedOut.resolve("mapping.tiny")))
        replay("analysis", failDir, failedOut, cli.output.resolve("failed-update-replay"))
        return failedOut
    }

    private fun rejectMigrationSelections(dir: Path, run: MigrationRun, reviews: List<MigrationReview>) {
        val ambiguous = run.tasks.single { caseFor(it).id == "becomesAmbiguous" }
        val invalid = MigrationReview(ambiguous.taskId, ambiguous.resolution.resolutionId, ambiguous.resolution.rule.revisionId,
            ReviewAction.ACCEPT, Confidence.HIGH, true, "High confidence cannot select one of two definite owners.")
        val invalidFile = cli.write("reviews/invalid-migration-accept.json", migrationBatch(run, listOf(invalid)))
        cli.execute("invalid-migration-accept", "migration", "submit", "--run", dir, "--review", invalidFile, expectedExit = 2)
        val obsolete = cli.gson.toJsonTree(migrationBatch(run, listOf(reviews.first()))).asJsonObject
        obsolete.getAsJsonArray("items")[0].asJsonObject.addProperty("targetDescriptor", "LcallerCannotChoose;")
        obsolete.getAsJsonArray("items")[0].asJsonObject.add("candidateComparisons", cli.gson.toJsonTree(emptyList<Any>()))
        val file = cli.write("reviews/obsolete-migration-selection.json", obsolete)
        cli.execute("obsolete-migration-selection", "migration", "submit", "--run", dir, "--review", file, expectedExit = 2)
    }

    private fun prepareAnalysis(version: String, rules: Path, dir: Path, base: Path? = null): AnalysisRun {
        val args = mutableListOf<Any>("analysis", "prepare", "--apk", apk(version), "--rules", rules, "--run", dir)
        base?.let { args.add("--base-knowledge"); args.add(it) }
        cli.execute("${dir.fileName}-prepare", *args.toTypedArray())
        return cli.read(dir.resolve("run.json"))
    }

    private fun prepareMigration(sourceOut: Path, dir: Path, overrides: Path? = null): MigrationRun {
        val args = mutableListOf<Any>("migration", "prepare", "--knowledge", sourceOut.resolve("knowledge.json"),
            "--source-apk", apk("v1"), "--target-apk", apk("v2"), "--run", dir)
        overrides?.let { args.add("--rules"); args.add(it) }
        cli.execute("${dir.fileName}-prepare", *args.toTypedArray())
        return cli.read(dir.resolve("run.json"))
    }

    private fun inspectAnalysis(dir: Path, run: AnalysisRun): List<EvidenceRecord> =
        cli.result<Array<EvidenceRecord>>("${dir.fileName}-inspect", "analysis", "inspect", "--run", dir,
            "--task", run.tasks.joinToString(",") { it.taskId }).toList().also { checkEvidence(dir, it) }

    private fun inspectMigration(dir: Path, run: MigrationRun): List<EvidenceRecord> =
        cli.result<Array<EvidenceRecord>>("${dir.fileName}-inspect", "migration", "inspect", "--run", dir,
            "--task", run.tasks.joinToString(",") { it.taskId }).toList().also { checkEvidence(dir, it) }

    private fun checkEvidence(dir: Path, evidence: List<EvidenceRecord>) {
        assertTrue(evidence.isNotEmpty())
        evidence.forEach { assertTrue(Files.size(dir.resolve(it.javaPath)) > 0); it.smaliPath?.let { p -> assertTrue(Files.size(dir.resolve(p)) > 0) } }
    }

    private fun analysisReview(run: AnalysisRun, task: AnalysisTask, evidence: List<EvidenceRecord>, version: String,
                               name: String, scenario: FixtureCase = caseFor(task)): AnalysisReview {
        // Assert the independent source-authored target before binding any review to runtime data.
        assertResolution(task.resolution, scenario, version)
        val owner = oracles.getValue(version).descriptor(scenario.versions.getValue(version).owners.single())
        val factory = oracles.getValue(version).descriptor(manifest.versions.getValue(version).factoryClass)
        val refs = setOf(owner, factory).map { raw -> evidence.single { it.ref.apkSha256 == run.apk.sha256 && it.ref.descriptor == raw } }
        return AnalysisReview(task.taskId, task.resolution.resolutionId, task.rule.revisionId, ReviewAction.ACCEPT, name, Confidence.HIGH,
            "Fixture source defines ${scenario.semanticAlias}: a component-scoped logger initialized by the shared logger factory. Confirmed semantic name comes from the fixture contract.",
            listOf("Runtime logging behavior and unavailable decompiled method bodies are outside this protocol regression."), refs.map { it.evidenceId })
    }

    private fun migrationReview(run: MigrationRun, task: MigrationTask, evidence: List<EvidenceRecord>): MigrationReview {
        val scenario = caseFor(task)
        val source = oracles.getValue("v1").descriptor(scenario.versions.getValue("v1").owners.single())
        val target = if (scenario.id == "becomesAmbiguous") sourceOwnerAtV2(scenario) else
            oracles.getValue("v2").descriptor(scenario.versions.getValue("v2").owners.single())
        assertEquals(ResolutionStatus.UNIQUE, task.resolution.status)
        assertEquals(setOf(target), task.resolution.candidates.map { it.ref.descriptor }.toSet())
        val records = listOf(run.sourceApk.sha256 to source, run.targetApk.sha256 to target).map { (sha, raw) ->
            evidence.single { it.ref.apkSha256 == sha && it.ref.descriptor == raw }
        }
        return MigrationReview(task.taskId, task.resolution.resolutionId, task.resolution.rule.revisionId, ReviewAction.ACCEPT, Confidence.HIGH, true,
            "Fixture source retains ${scenario.semanticAlias}'s component responsibility across the two controlled versions.",
            listOf("Business tag, factory method and R8-generated symbols change between fixture versions."),
            listOf("This source-authored fixture review does not evaluate Agent judgement or APK runtime behavior."), records.map { it.evidenceId })
    }

    private fun analysisBatch(run: AnalysisRun, reviews: List<AnalysisReview>) = AnalysisReviewBatch(runId = run.runId, apkSha256 = run.apk.sha256, items = reviews)
    private fun migrationBatch(run: MigrationRun, reviews: List<MigrationReview>) = MigrationReviewBatch(runId = run.runId,
        sourceKnowledgeId = run.knowledge.knowledgeId, sourceApkSha256 = run.sourceApk.sha256, targetApkSha256 = run.targetApk.sha256, items = reviews)
    private fun rejectAnalysis(dir: Path, run: AnalysisRun, reviews: List<AnalysisReview>, label: String) {
        val path = cli.write("reviews/$label.json", analysisBatch(run, reviews))
        cli.execute(label, "analysis", "submit", "--run", dir, "--review", path, expectedExit = 2)
    }
    private fun analysisPage(dir: Path): AnalysisTaskPage = cli.result("${dir.fileName}-tasks", "analysis", "tasks", "--run", dir, "--state", "ALL", "--limit", 100)
    private fun publish(scene: String, run: Path, out: Path): VersionKnowledge {
        cli.execute("${out.fileName}", scene, "publish", "--run", run, "--out", out)
        return cli.read(out.resolve("knowledge.json"))
    }
    private fun replay(scene: String, run: Path, first: Path, replay: Path) {
        cli.execute("${replay.fileName}", scene, "publish", "--run", run, "--out", replay, "--at", first.resolve("report.json"))
        for (file in listOf("knowledge.json", "mapping.tiny")) assertEquals(Files.readString(first.resolve(file)), Files.readString(replay.resolve(file)), "Replay $file")
    }

    private fun assertResolution(resolution: Resolution, scenario: FixtureCase, version: String) {
        val expected = scenario.versions.getValue(version)
        assertEquals(expected.resolution, resolution.status.name, "${scenario.id} $version status")
        assertEquals(expected.owners.map(oracles.getValue(version)::descriptor).toSet(), resolution.candidates.map { it.ref.descriptor }.toSet(), "${scenario.id} $version identities")
        assertEquals("apk-all-dex", resolution.searchScope)
        assertTrue(resolution.candidates.all { it.ref.apkSha256 == resolution.apkSha256 && it.ref.dexEntry.matches(Regex("classes[0-9]*\\.dex")) })
        if (resolution.status == ResolutionStatus.UNIQUE) {
            val matches = resolution.candidates.single().matches.filter { it.status == MatchStatus.PASS }
            assertTrue(matches.isNotEmpty())
            assertTrue(matches.all { it.captures["component"] == scenario.component && it.factors.all { factor -> factor.status == MatchStatus.PASS } })
        }
    }
    private fun assertKnowledge(knowledge: VersionKnowledge, expected: Map<String, String>) {
        assertEquals(expected, knowledge.entries.associate { it.binding.descriptor to it.name })
        assertEquals(knowledge.entries.size, knowledge.entries.map { it.semanticId }.distinct().size)
        assertTrue(knowledge.entries.all { it.binding.apkSha256 == knowledge.artifact.sha256 && it.resolution?.status == ResolutionStatus.UNIQUE && it.resolution?.uniqueRef == it.binding })
    }
    private fun assertUnresolved(knowledge: VersionKnowledge, source: VersionKnowledge, expectedCaseIds: Set<String>) {
        assertEquals(expectedCaseIds.map { scenario(it).semanticAlias }.toSet(), knowledge.unresolved.map { it.entry.name }.toSet())
        knowledge.unresolved.forEach { unresolved ->
            val original = source.entries.single { it.semanticId == unresolved.entry.semanticId }
            assertEquals(original, unresolved.entry)
            assertEquals(source.knowledgeId, unresolved.sourceKnowledgeId)
            assertNotEquals(knowledge.artifact.sha256, unresolved.entry.binding.apkSha256)
        }
    }
    private fun assertMappingAndVerify(out: Path, version: String, expected: Map<String, String>) {
        val rows = Files.readAllLines(out.resolve("mapping.tiny"))
        assertEquals("tiny\t2\t0\tobfuscated\tnamed", rows.first())
        assertTrue(rows.drop(1).all { it.startsWith("c\t") }, "Mapping must contain only class rows")
        val mapped = rows.drop(1).associate { line -> line.split('\t').let { "L${it[1]};" to it[2].replace('/', '.') } }
        val display = expected.mapValues { (descriptor, alias) -> displayedName(descriptor, alias) }
        assertEquals(display, mapped)
        val verified = cli.result<Array<VerifiedRename>>("${out.fileName}-jadx-readback", "knowledge", "verify", "--knowledge", out.resolve("knowledge.json"),
            "--apk", apk(version), "--work", out.resolve("independent-readback"))
        assertEquals(display, verified.associate { it.descriptor to it.displayedName })
        verified.forEach { assertEquals(it.descriptor.removePrefix("L").removeSuffix(";").replace('/', '.'), it.rawName) }
    }

    private fun locator(component: String, tag: String? = null): Locator = Locator("field-initializer", component,
        factors(tag, component), listOf(CaptureSpec("component", 1)))
    private fun factors(tag: String?, component: String?): List<FactorSpec> = listOf(
        FactorSpec("field-flags", requiredFlags = listOf("STATIC", "FINAL")),
        FactorSpec("invocation-kind", invocationKind = "STATIC"),
        FactorSpec("method-signature", parameterTypes = listOf("Ljava/lang/String;", "Ljava/lang/String;"), returnSameAsField = true),
        FactorSpec("argument-string", index = 0, value = tag), FactorSpec("argument-string", index = 1, value = component), FactorSpec("assignment-owner"))
    private fun profile(tag: String) = AnalysisProfile(id = "fixture-logger-fields", discovery = Locator("field-initializer", tag,
        factors(tag, null), listOf(CaptureSpec("component", 1))), nameCapture = "component", locatorTemplate = LocatorTemplate("field-initializer", "component",
        factors(null, null).map { if (it.kind == "argument-string" && it.index == 1) it.copy(valueFromCapture = "component") else it }, listOf(CaptureSpec("component", 1))))
    private fun caseFor(task: AnalysisTask): FixtureCase = manifest.cases.single { it.component == task.request.locators.first().anchor }
    private fun caseFor(task: MigrationTask): FixtureCase = manifest.cases.single { it.semanticAlias == task.entry.name }
    private fun scenario(id: String) = manifest.cases.single { it.id == id }
    private fun sourceOwnerAtV2(scenario: FixtureCase) = oracles.getValue("v2").descriptor(scenario.versions.getValue("v1").owners.single())
    private fun apk(version: String) = repo.resolve(manifest.versions.getValue(version).apk)
    private fun displayedName(descriptor: String, alias: String): String = descriptor.removePrefix("L").removeSuffix(";")
        .substringBeforeLast('/', "").let { if (it.isEmpty()) alias else "${it.replace('/', '.')}.$alias" }
    private fun requiredPath(property: String): Path = Path.of(requireNotNull(System.getProperty(property)) { "Run ./gradlew fixtureIntegrationTest; missing $property" }).toAbsolutePath()
}
