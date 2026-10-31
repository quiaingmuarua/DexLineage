package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path
import com.google.gson.JsonParser

/** Opaque diagnostic files from matching; Migration does not interpret scenario payloads. */
internal object MigrationArtifacts {
    fun fromPackage(report: Artifact, knowledgeId: String): List<ScenarioArtifactRef> {
        Digests.verify(report)
        val path = Path.of(report.path); val root = path.parent.toAbsolutePath().normalize()
        val value = JsonParser.parseString(Files.readString(path)).asJsonObject
        requireInput(value["schemaVersion"]?.asInt == SCHEMA_VERSION && value["knowledgeId"]?.asString == knowledgeId, "Inherited method artifacts have an inconsistent package report")
        return value.getAsJsonArray("methodArtifacts")?.map { element ->
            val ref = JsonFiles.gson.fromJson(element, ScenarioArtifactRef::class.java)
            val file = root.resolve(ref.path).toAbsolutePath().normalize()
            requireInput(file.startsWith(root), "Inherited method artifact escapes target base package")
            ref.copy(path = file.toString())
        }.orEmpty().distinct().also(::verify)
    }

    fun verify(refs: List<ScenarioArtifactRef>) {
        refs.forEach { ref ->
            requireInput(ref.kind.isNotBlank(), "Missing migration method artifact kind")
            Digests.verify(Artifact(ref.path, ref.sha256))
        }
    }

    fun copy(refs: List<ScenarioArtifactRef>, out: Path): List<ScenarioArtifactRef> {
        verify(refs)
        if (refs.isEmpty()) return emptyList()
        val folder = out.toAbsolutePath().normalize().resolve("method-artifacts")
        Files.createDirectories(folder)
        return refs.distinct().mapIndexed { index, ref ->
            val path = folder.resolve("$index-${ref.sha256}.json")
            Files.copy(Path.of(ref.path), path)
            requireInput(Digests.file(path) == ref.sha256, "Copied migration artifact changed")
            ScenarioArtifactRef(ref.kind, path.toString(), ref.sha256)
        }
    }
}
