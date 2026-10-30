package dev.dexlineage.migration.legacy

import dev.dexlineage.model.*

/** Exact schema-3 serialization shapes. Never add schema-4 defaults when checking old digests. */
internal data class V03Rule(val revisionId: String, val locators: List<Locator>)
internal data class V03Match(val owner: ClassRef, val status: MatchStatus, val factors: List<FactorResult>, val captures: Map<String, String>,
    val field: FieldBinding? = null, val stringUses: List<StringUseSite> = emptyList(), val locatorIndex: Int = 0)
internal data class V03Candidate(val ref: ClassRef, val status: MatchStatus, val matches: List<V03Match>)
internal data class V03Resolution(val schemaVersion: Int, val resolutionId: String, val apkSha256: String, val rule: V03Rule,
    val engineVersion: String, val engineBuildId: String, val searchScope: String,
    val status: ResolutionStatus, val candidates: List<V03Candidate>, val matches: List<V03Match>)
internal data class V03Entry(val semanticId: String, val name: String, val binding: ClassRef, val captures: Map<String, String>,
    val locators: List<Locator>, val evidence: List<KnowledgeEvidence>, val rationale: String, val provenance: String,
    val ruleRevision: V03Rule? = null, val resolution: V03Resolution? = null) {
    fun historicalEntry(): KnowledgeEntry = KnowledgeEntry(semanticId, name, binding, captures, locators, evidence, rationale, provenance)
}
internal data class V03Unresolved(val entry: V03Entry, val sourceKnowledgeId: String, val reason: String, val originRun: String) {
    fun historical(): UnresolvedKnowledge = UnresolvedKnowledge(entry.historicalEntry(), sourceKnowledgeId, reason, originRun)
}
internal data class V03Knowledge(val schemaVersion: Int, val kind: String, val knowledgeId: String, val artifact: Artifact,
    val entries: List<V03Entry>, val unresolved: List<V03Unresolved>, val provenance: String, val parentKnowledgeId: String? = null)
