package dev.dexlineage.knowledge

import dev.dexlineage.io.*
import dev.dexlineage.model.*

/** Immutable proof data. APK execution is owned by the JADX adapter. */
object RuleProofs {
    fun revision(locators: List<Locator>): RuleRevision {
        requireInput(locators.isNotEmpty(), "A rule revision requires at least one locator")
        val normalized = locators.distinct()
        return RuleRevision(Digests.text(JsonFiles.encode(normalized)), normalized)
    }

    fun validate(rule: RuleRevision) = checkedInput("rule revision") {
        requireInput(rule == revision(rule.locators), "Rule revision digest mismatch")
    }

    fun create(apkSha256: String, rule: RuleRevision, engineBuildId: String, matches: List<MatchFact>): Resolution {
        validate(rule)
        requireInput(engineBuildId.isNotBlank(), "Missing matching engine build identity")
        requireInput(matches.all { it.owner.apkSha256 == apkSha256 && it.locatorIndex in rule.locators.indices }, "Rule facts belong to another APK or locator")
        val sorted = matches.sortedWith(compareBy({ it.locatorIndex }, { it.owner.descriptor }, { it.field?.fieldName.orEmpty() }, { it.field?.fieldType.orEmpty() }))
        val candidates = sorted.filter { it.status != MatchStatus.FAIL }.groupBy { it.owner.descriptor }.toSortedMap().map { (_, facts) ->
            requireInput(facts.map { it.owner }.distinct().size == 1, "Conflicting original class identities")
            ResolutionCandidate(facts.first().owner, if (facts.any { it.status == MatchStatus.PASS }) MatchStatus.PASS else MatchStatus.UNKNOWN, facts)
        }
        val passCount = candidates.count { it.status == MatchStatus.PASS }
        val status = when {
            passCount >= 2 -> ResolutionStatus.AMBIGUOUS
            candidates.isEmpty() -> ResolutionStatus.NO_MATCH
            candidates.size == 1 && passCount == 1 -> ResolutionStatus.UNIQUE
            else -> ResolutionStatus.UNKNOWN
        }
        val draft = Resolution(resolutionId = "", apkSha256 = apkSha256, rule = rule, engineBuildId = engineBuildId,
            status = status, candidates = candidates, matches = sorted)
        return draft.copy(resolutionId = id(draft))
    }

    fun id(value: Resolution): String = Digests.text(JsonFiles.encode(value.copy(resolutionId = "")))

    /** A compact capture summary; conflicting alternatives remain explicit in the full proof. */
    fun captures(value: Resolution): Map<String, String> = value.matches
        .filter { it.owner == value.uniqueRef && it.status == MatchStatus.PASS }
        .flatMap { it.captures.entries }.groupBy({ it.key }, { it.value })
        .mapNotNull { (key, values) -> values.distinct().singleOrNull()?.let { key to it } }.toMap().toSortedMap()

    fun validate(value: Resolution) = checkedInput("resolution") {
        requireInput(value.schemaVersion == SCHEMA_VERSION && value.engineVersion == TOOL_VERSION && value.searchScope == "apk-all-dex", "Unsupported resolution contract")
        val rebuilt = create(value.apkSha256, value.rule, value.engineBuildId, value.matches)
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
        }
    }
}
