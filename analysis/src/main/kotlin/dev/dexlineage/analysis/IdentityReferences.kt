package dev.dexlineage.analysis

import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.knowledge.*
import dev.dexlineage.mapping.MappingOutput
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path

/** Read-only canonical identities. Reference rules, anchors and reviews are never executed or inherited. */
internal object IdentityReferences {
    fun load(paths: List<Path>, apk: Artifact, base: VersionKnowledge?): List<IdentityReference>? {
        if (paths.isEmpty()) return null
        val resolved = paths.map { it.toAbsolutePath().normalize() }
        requireInput(resolved.distinct().size == resolved.size, "Duplicate identity reference path")
        val references = resolved.map { path ->
            val file = Digests.artifact(path)
            val knowledge = KnowledgeFiles.read(path)
            requireInput(knowledge.artifact.sha256 == apk.sha256, "Identity reference belongs to another APK")
            val mapping = Digests.artifact(path.parent.resolve("mapping.tiny"))
            val report = Digests.artifact(path.parent.resolve("report.json"))
            verifyPackage(knowledge, mapping, report)
            IdentityReference(file, knowledge, mapping, report)
        }.sortedBy { it.knowledge.knowledgeId }
        validate(references, apk, base)
        return references
    }

    fun validate(references: List<IdentityReference>?, apk: Artifact, base: VersionKnowledge?) {
        val values = references.orEmpty()
        requireInput(values.map { it.file.path }.distinct().size == values.size &&
            values.map { it.knowledge.knowledgeId }.distinct().size == values.size, "Duplicate identity reference package")
        values.forEach { reference ->
            val knowledge = reference.knowledge
            requireInput(knowledge.artifact.sha256 == apk.sha256 && knowledge.knowledgeId == KnowledgeFiles.id(knowledge), "Frozen identity reference differs from its APK or revision")
            knowledge.entries.forEach { entry ->
                requireInput(entry.binding.apkSha256 == apk.sha256, "Referenced identity belongs to another APK")
                Identities.renamedFullName(entry.binding.descriptor, entry.name)
                val proof = entry.resolution ?: throw ValidationException("Referenced identity lacks a matching proof")
                RuleProofs.validate(proof)
                requireInput(proof.uniqueRef == entry.binding && proof.rule == entry.ruleRevision, "Referenced identity has an inconsistent binding proof")
            }
        }
        // A same-version pending binding already owns its semantic identity. References cannot
        // bypass explicit retry by introducing a different ID for that still-owned class.
        val entries = base?.entries.orEmpty() + base?.unresolved.orEmpty().map { it.entry }
            .filter { it.binding.apkSha256 == apk.sha256 } + values.flatMap { it.knowledge.entries }
        entries.groupBy { it.binding }.values.forEach { group ->
            requireInput(group.map { it.semanticId to it.name }.distinct().size == 1, "Conflicting canonical identities or names for one class binding")
        }
        entries.groupBy { it.semanticId }.values.forEach { group ->
            requireInput(group.map { it.binding to it.name }.distinct().size == 1, "Canonical identity refers to conflicting class bindings or names")
        }
        val pending = base?.unresolved.orEmpty().associateBy { it.entry.semanticId }
        values.flatMap { it.knowledge.entries }.forEach { entry ->
            pending[entry.semanticId]?.let {
                requireInput(it.entry.binding == entry.binding && it.entry.name == entry.name,
                    "Reference cannot claim a historical unresolved identity for another binding")
            }
        }
    }

    fun verifyFiles(references: List<IdentityReference>?) {
        references.orEmpty().forEach { reference ->
            listOf(reference.file, reference.mappingFile, reference.reportFile).forEach(Digests::verify)
            requireInput(KnowledgeFiles.read(Path.of(reference.file.path)) == reference.knowledge, "Identity reference package differs from frozen input")
            verifyPackage(reference.knowledge, reference.mappingFile, reference.reportFile)
        }
    }

    private fun verifyPackage(knowledge: VersionKnowledge, mapping: Artifact, report: Artifact) {
        MappingOutput.verifyContents(Path.of(mapping.path), knowledge.entries.map {
            AcceptedRename(it.binding.descriptor, Identities.renamedFullName(it.binding.descriptor, it.name))
        })
        val json = JsonParser.parseString(Files.readString(Path.of(report.path))).asJsonObject
        requireInput(json.get("schemaVersion")?.asInt == SCHEMA_VERSION && json.get("knowledgeId")?.asString == knowledge.knowledgeId,
            "Identity reference report differs from its knowledge revision")
    }

    fun byId(references: List<IdentityReference>?, id: String): KnowledgeEntry? =
        references.orEmpty().flatMap { it.knowledge.entries }.firstOrNull { it.semanticId == id }

    fun byBinding(references: List<IdentityReference>?, binding: ClassRef): Pair<KnowledgeEntry, String>? =
        references.orEmpty().firstNotNullOfOrNull { reference ->
            reference.knowledge.entries.singleOrNull { it.binding == binding }?.let { it to reference.knowledge.knowledgeId }
        }
}
