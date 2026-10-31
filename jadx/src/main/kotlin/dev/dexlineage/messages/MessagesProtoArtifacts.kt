package dev.dexlineage.messages

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import java.nio.file.Path

data class ProtoMetadataObject(val index: Int, val kind: String, val text: String? = null, val type: String? = null)
data class ProtoMetadataSite(val source: MethodRef, val codeUnitOffset: Int, val status: String,
    val factory: MethodRef? = null, val info: String? = null, val objects: List<ProtoMetadataObject> = emptyList(),
    val defaultField: String? = null, val diagnostics: List<String> = emptyList(), val metadataConstructor: MethodRef? = null)
data class ProtoFieldFact(val fieldNumber: Int, val cardinality: String, val kind: String,
    val fieldName: String, val fieldType: String, val metadataTypeId: Int, val relatedType: ClassRef?,
    val source: MethodRef, val codeUnitOffset: Int)
data class ProtoPathProblem(val source: MethodRef, val codeUnitOffset: Int?, val reason: String,
    val fieldNumber: Int? = null, val cardinality: String? = null) {
    fun uncertainty() = MatchUncertainty(source, codeUnitOffset, reason)
}
data class ProtoFieldCatalogue(val schemaVersion: Int = SCHEMA_VERSION, val kind: String = MessagesProtoArtifacts.KIND,
    val apkSha256: String, val parent: ClassRef, val metadata: List<ProtoMetadataSite>,
    val fields: List<ProtoFieldFact>, val unresolvedPaths: List<ProtoPathProblem>)

/** Typed one-hop facts. The catalogue does not authorize a rename or replace a Resolution. */
object MessagesProtoArtifacts {
    const val KIND = "messages.proto-fields"

    fun read(refs: List<ScenarioArtifactRef>): ProtoFieldCatalogue? {
        val selected = refs.filter { it.kind == KIND }.distinctBy { it.sha256 }
        if (selected.isEmpty()) return null
        requireInput(selected.size == 1, "Expected one Proto parent catalogue")
        val ref = selected.single()
        Digests.verify(Artifact(ref.path, ref.sha256))
        return JsonFiles.read(Path.of(ref.path), ProtoFieldCatalogue::class.java).also(::validate)
    }

    fun validate(value: ProtoFieldCatalogue) {
        requireInput(value.schemaVersion == SCHEMA_VERSION && value.kind == KIND && value.parent.apkSha256 == value.apkSha256, "Invalid Proto catalogue identity")
        RuleProofs.validateEntity(EntityRef(value.parent))
        fun method(ref: MethodRef) {
            RuleProofs.validateEntity(EntityRef(ref.owner, ref))
            requireInput(ref.owner.apkSha256 == value.apkSha256, "Proto catalogue method belongs to another APK")
        }
        value.metadata.forEach { site ->
            method(site.source); site.factory?.let(::method); site.metadataConstructor?.let(::method)
            requireInput(site.source.owner == value.parent && site.codeUnitOffset >= 0 && site.status in setOf("RESOLVED", "UNKNOWN"), "Invalid Proto metadata site")
            requireInput(site.objects.map { it.index }.distinct().size == site.objects.size && site.objects.all { it.index >= 0 && it.kind in setOf("STRING", "CLASS", "UNKNOWN") }, "Invalid Proto metadata objects")
        }
        value.fields.forEach { field ->
            method(field.source)
            requireInput(field.source.owner == value.parent && field.fieldNumber in 1..536870911 && field.cardinality in setOf("singular", "repeated") &&
                field.kind in setOf("message", "scalar") && field.fieldName.isNotBlank() && field.codeUnitOffset >= 0, "Invalid Proto field fact")
            requireInput((field.kind == "message") == (field.relatedType != null), "Proto message type is missing or invented")
            field.relatedType?.let { requireInput(it.apkSha256 == value.apkSha256, "Proto child belongs to another APK"); RuleProofs.validateEntity(EntityRef(it)) }
            requireInput(value.metadata.any { it.source == field.source && it.codeUnitOffset == field.codeUnitOffset && it.status == "RESOLVED" }, "Proto field has no complete metadata site")
        }
        value.unresolvedPaths.forEach { path ->
            method(path.source)
            requireInput(path.source.owner == value.parent && (path.codeUnitOffset == null || path.codeUnitOffset >= 0) && path.reason.isNotBlank(), "Invalid Proto unresolved path")
            requireInput(path.fieldNumber == null || path.fieldNumber in 1..536870911, "Invalid unresolved field number")
            requireInput(path.cardinality == null || path.cardinality in setOf("singular", "repeated"), "Invalid unresolved field cardinality")
        }
    }
}
