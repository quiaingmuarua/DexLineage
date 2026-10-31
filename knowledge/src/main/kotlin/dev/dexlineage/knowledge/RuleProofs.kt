package dev.dexlineage.knowledge

import dev.dexlineage.io.*
import dev.dexlineage.model.*

/** Immutable proof data. APK execution is owned by the JADX adapter. */
object RuleProofs {
    fun revision(locators: List<Locator>, strategy: StrategySpec? = null): RuleRevision = revision(
        if (strategy == null) RuleRevision(locators = locators) else {
            requireInput(locators.isEmpty(), "Use either locators or a strategy")
            RuleRevision(strategyId = strategy.strategyId, parameters = strategy.parameters,
                resultKind = strategy.resultKind, requires = strategy.requires)
        })

    fun revision(rule: RuleRevision): RuleRevision {
        requireInput(rule.strategyId.matches(Regex("[a-z][a-z0-9.-]*")), "Invalid strategy ID")
        requireInput(rule.resultKind != null, "Missing strategy result kind")
        requireInput(rule.requires.all { (role, key) -> validKey(role) && validKey(key) }, "Invalid dependency role/key")
        if (rule.strategyId == "builtin.locators") {
            requireInput(rule.locators.isNotEmpty() && rule.resultKind == EntityKind.CLASS && rule.requires.isEmpty() && rule.parameters.size() == 0,
                "Built-in locators require class results and no strategy parameters/dependencies")
        } else requireInput(rule.locators.isEmpty(), "Coded strategies do not accept locator input")
        val normalized = rule.copy(revisionId = "", locators = rule.locators.distinct(),
            parameters = canonical(rule.parameters).asJsonObject, requires = rule.requires.toSortedMap())
        return normalized.copy(revisionId = Digests.text(JsonFiles.encode(normalized)))
    }

    fun validate(rule: RuleRevision) = checkedInput("rule revision") {
        requireInput(rule == revision(rule), "Rule revision digest mismatch")
    }

    fun create(apkSha256: String, rule: RuleRevision, engineBuildId: String, matches: List<MatchFact>,
               dependencies: Map<String, SupportAnchor> = emptyMap(), unresolvedPaths: List<UnresolvedPath>? = null): Resolution {
        validate(rule)
        requireInput(engineBuildId.isNotBlank(), "Missing matching engine build identity")
        requireInput(dependencies.keys == rule.requires.keys, "Resolution dependencies differ from declared roles")
        dependencies.forEach { (role, anchor) ->
            requireInput(anchor.key == rule.requires[role] && anchor.binding.owner.apkSha256 == apkSha256, "Dependency belongs to another key/APK")
            validateAnchor(anchor, apkSha256)
        }
        val indices = if (rule.strategyId == "builtin.locators") rule.locators.indices else 0..0
        requireInput(matches.all { it.owner.apkSha256 == apkSha256 && it.locatorIndex in indices }, "Rule facts belong to another APK or locator")
        matches.forEach { match ->
            requireInput(EntityRef(match.owner, match.method).kind == rule.resultKind, "Fact entity kind differs from rule")
            validateEntity(EntityRef(match.owner, match.method))
        }
        val unresolved = unresolvedPaths.orEmpty().distinct().sortedWith(compareBy(
            { EntityRef(it.source.owner, it.source).identity }, { it.codeUnitOffset ?: -1 }, { JsonFiles.encode(it) }))
        unresolved.forEach { path ->
            validateEntity(EntityRef(path.source.owner, path.source))
            requireInput(path.source.owner.apkSha256 == apkSha256, "Unresolved path belongs to another APK")
            requireInput(path.codeUnitOffset == null || path.codeUnitOffset >= 0, "Invalid unresolved path offset")
            requireInput(path.reason.isNotBlank(), "Unresolved path needs a reason")
        }
        val sorted = matches.sortedWith(compareBy({ it.locatorIndex }, { EntityRef(it.owner, it.method).identity },
            { it.field?.fieldName.orEmpty() }, { it.field?.fieldType.orEmpty() }, { JsonFiles.encode(it) }))
        val candidates = sorted.filter { it.status != MatchStatus.FAIL }.groupBy { EntityRef(it.owner, it.method).identity }.toSortedMap().map { (_, facts) ->
            requireInput(facts.map { EntityRef(it.owner, it.method) }.distinct().size == 1, "Conflicting original entity identities")
            ResolutionCandidate(facts.first().owner, if (facts.any { it.status == MatchStatus.PASS }) MatchStatus.PASS else MatchStatus.UNKNOWN, facts, facts.first().method)
        }
        val passCount = candidates.count { it.status == MatchStatus.PASS }
        val status = when {
            passCount >= 2 -> ResolutionStatus.AMBIGUOUS
            unresolved.isNotEmpty() -> ResolutionStatus.UNKNOWN
            candidates.isEmpty() -> ResolutionStatus.NO_MATCH
            candidates.size == 1 && passCount == 1 -> ResolutionStatus.UNIQUE
            else -> ResolutionStatus.UNKNOWN
        }
        val draft = Resolution(resolutionId = "", apkSha256 = apkSha256, rule = rule, engineBuildId = engineBuildId,
            status = status, candidates = candidates, matches = sorted, dependencies = dependencies.toSortedMap(),
            unresolvedPaths = unresolved.takeIf { it.isNotEmpty() })
        return draft.copy(resolutionId = id(draft))
    }

    fun id(value: Resolution): String = Digests.text(JsonFiles.encode(value.copy(resolutionId = "")))

    /** A compact capture summary; conflicting alternatives remain explicit in the full proof. */
    fun captures(value: Resolution): Map<String, String> = value.matches
        .filter { EntityRef(it.owner, it.method) == value.uniqueEntity && it.status == MatchStatus.PASS }
        .flatMap { it.captures.entries }.groupBy({ it.key }, { it.value })
        .mapNotNull { (key, values) -> values.distinct().singleOrNull()?.let { key to it } }.toMap().toSortedMap()

    fun validate(value: Resolution) = checkedInput("resolution") {
        requireInput(value.schemaVersion == SCHEMA_VERSION && value.engineVersion == TOOL_VERSION && value.searchScope == "apk-all-dex", "Unsupported resolution contract")
        val rebuilt = create(value.apkSha256, value.rule, value.engineBuildId, value.matches, value.dependencies, value.unresolvedPaths)
        requireInput(rebuilt == value, "Resolution identity or candidate result mismatch")
        value.matches.forEach { match ->
            Identities.requireDescriptor(match.owner.descriptor)
            requireInput(match.factors.isNotEmpty(), "Match has no condition evidence")
            val computed = when {
                match.factors.any { it.status == MatchStatus.FAIL } -> MatchStatus.FAIL
                match.factors.any { it.status == MatchStatus.UNKNOWN } -> MatchStatus.UNKNOWN
                else -> MatchStatus.PASS
            }
            requireInput(computed == match.status, "Match status disagrees with its condition evidence")
            requireInput(match.field == null || match.field.owner == match.owner, "Field evidence owner mismatch")
            requireInput((match.relatedRefs + match.trace.map { it.owner }).all { it.apkSha256 == value.apkSha256 }, "Related evidence belongs to another APK")
        }
    }

    fun validateEntity(entity: EntityRef) {
        Identities.requireDescriptor(entity.owner.descriptor)
        requireInput(entity.owner.dexEntry.matches(Regex("classes(?:[0-9]+)?\\.dex")), "Invalid DEX entry")
        entity.method?.let {
            requireInput(it.owner == entity.owner && it.name.isNotBlank() && it.descriptor.matches(Regex("\\([^)]*\\).+")), "Invalid method identity")
        }
    }

    fun validateAnchor(anchor: SupportAnchor, apkSha256: String? = null) {
        requireInput(validKey(anchor.key), "Invalid anchor key")
        validateEntity(anchor.binding)
        requireInput(apkSha256 == null || anchor.binding.owner.apkSha256 == apkSha256, "Anchor APK mismatch")
        requireInput(anchor.key !in anchor.rule.requires.values, "Anchor cannot depend on itself")
        validate(anchor.resolution)
        requireInput(anchor.rule == anchor.resolution.rule && anchor.resolution.uniqueEntity == anchor.binding, "Anchor requires a unique matching proof")
    }

    /** Structural declaration validation only; scenarios retain lifecycle ownership. */
    fun validateDependencies(definitions: Map<String, RuleRevision>, targets: List<RuleRevision>, available: Collection<SupportAnchor>) {
        val known = available.associateBy { it.key }.mapValues { it.value.rule } + definitions
        requireInput(available.map { it.key }.distinct().size == available.size, "Duplicate anchor key")
        (known.values + targets).forEach { rule -> validate(rule); requireInput(rule.requires.values.all { it in known }, "Missing anchor definition") }
        fun visit(key: String, path: Set<String>) {
            requireInput(key !in path, "Cyclic anchor dependency: $key")
            known.getValue(key).requires.values.forEach { visit(it, path + key) }
        }
        known.keys.forEach { visit(it, emptySet()) }
    }

    private fun validKey(value: String): Boolean = value.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}"))
    private fun canonical(value: com.google.gson.JsonElement): com.google.gson.JsonElement = when {
        value.isJsonObject -> com.google.gson.JsonObject().also { out -> value.asJsonObject.entrySet().sortedBy { it.key }.forEach { out.add(it.key, canonical(it.value)) } }
        value.isJsonArray -> com.google.gson.JsonArray().also { out -> value.asJsonArray.forEach { out.add(canonical(it)) } }
        else -> value.deepCopy()
    }
}
