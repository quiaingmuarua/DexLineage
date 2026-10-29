package dev.dexlineage.analysis

import com.google.gson.JsonParser
import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import java.nio.file.Files
import java.nio.file.Path

/** Original annotations are research inputs, never executable target filters or accepted knowledge. */
object ManualCorpusFiles {
    fun importJadx(apkPath: Path, projectPath: Path, output: Path): ManualCorpus = checkedInput("JADX annotation corpus") {
        val apk = Digests.artifact(apkPath)
        val project = Digests.artifact(projectPath)
        val json = JsonParser.parseString(Files.readString(projectPath)).asJsonObject
        requireInput(json.get("projectVersion")?.asInt == 1, "Only JADX projectVersion=1 annotations are supported")
        val renames = json.getAsJsonObject("codeData")?.getAsJsonArray("renames")
            ?: throw ValidationException("JADX project has no codeData.renames array")
        val scan = ApkReader.scan(apkPath, emptySet())
        if (scan.stats.diagnostics.isNotEmpty()) throw ExecutionException("Cannot import annotations from an incomplete APK scan")
        val members = ApkReader.memberInventory(apkPath)
        val annotations = renames.map { element ->
            val original = element.asJsonObject
            val node = original.getAsJsonObject("nodeRef") ?: throw ValidationException("Annotation has no nodeRef")
            val refType = node.get("refType")?.asString ?: throw ValidationException("Annotation has no refType")
            requireInput(refType in setOf("CLASS", "FIELD", "METHOD"), "Unsupported annotation reference: $refType")
            val owner = "L${node.get("declClass")?.asString?.replace('.', '/') ?: throw ValidationException("Annotation has no owner")};"
            Identities.requireDescriptor(owner)
            requireInput(owner in scan.classes, "Annotation class is absent from supplied APK: $owner")
            val member = node.get("shortId")?.asString
            if (refType != "CLASS") requireInput(!member.isNullOrBlank() && member in members[owner].orEmpty(), "Annotation member is absent from supplied APK: $owner->$member")
            val codeRef = original.get("codeRef")?.takeUnless { it.isJsonNull }?.asJsonObject
            requireInput(codeRef == null || refType == "METHOD", "Local annotation must reference a method")
            val name = original.get("newName")?.asString ?: throw ValidationException("Annotation has no name")
            requireInput(name.isNotBlank(), "Annotation name is empty")
            ManualAnnotation(if (codeRef == null) refType else "LOCAL_${codeRef.get("attachType")?.asString ?: "UNKNOWN"}",
                owner, member, name, codeRef?.deepCopy(), original.deepCopy())
        }
        val targets = annotations.mapIndexedNotNull { index, annotation ->
            if (annotation.kind != "CLASS") null else ManualTarget(targetId(apk.sha256, annotation.ownerDescriptor),
                ClassRef(apk.sha256, annotation.ownerDescriptor, scan.classes.getValue(annotation.ownerDescriptor)), annotation.name, index)
        }.sortedBy { it.targetId }
        requireInput(targets.map { it.source }.distinct().size == targets.size, "Duplicate class annotation")
        val draft = ManualCorpus(corpusId = "", apk = apk, project = project, projectVersion = 1,
            annotations = annotations, targets = targets, annotationCounts = annotations.groupingBy { it.kind }.eachCount().toSortedMap())
        val corpus = draft.copy(corpusId = draft.fingerprint())
        listOf(apk, project).forEach(Digests::verify)
        createNewDirectory(output)
        JsonFiles.writeNew(output.resolve("corpus.json"), corpus)
        corpus
    }

    fun read(path: Path, verifyInputs: Boolean = true): ManualCorpus = checkedInput("manual corpus") {
        val corpus = JsonFiles.read(path, ManualCorpus::class.java)
        validate(corpus)
        if (verifyInputs) {
            listOf(corpus.apk, corpus.project).forEach(Digests::verify)
            val project = JsonParser.parseString(Files.readString(Path.of(corpus.project.path))).asJsonObject
            val originals = project.getAsJsonObject("codeData")?.getAsJsonArray("renames")?.map { it.asJsonObject }
            requireInput(project.get("projectVersion")?.asInt == corpus.projectVersion && originals == corpus.annotations.map { it.original }, "Corpus annotations differ from the original JADX project")
        }
        corpus
    }

    fun validate(corpus: ManualCorpus) {
        requireInput(corpus.schemaVersion == SCHEMA_VERSION && corpus.kind == "manual-corpus" && corpus.projectVersion == 1, "Unsupported manual corpus")
        requireInput(corpus.corpusId == corpus.fingerprint(), "Manual corpus fingerprint mismatch")
        requireInput(corpus.annotationCounts == corpus.annotations.groupingBy { it.kind }.eachCount().toSortedMap(), "Corpus annotation counts changed")
        corpus.annotations.forEach { a ->
            val node = a.original.getAsJsonObject("nodeRef")
            val codeRef = a.original.get("codeRef")?.takeUnless { it.isJsonNull }?.asJsonObject
            val kind = if (codeRef == null) node.get("refType").asString else "LOCAL_${codeRef.get("attachType")?.asString ?: "UNKNOWN"}"
            requireInput(a.kind == kind && a.ownerDescriptor == "L${node.get("declClass").asString.replace('.', '/')};" && a.memberId == node.get("shortId")?.asString &&
                a.name == a.original.get("newName").asString && a.codeRef == codeRef, "Corpus annotation differs from its original data")
        }
        val targets = corpus.annotations.withIndex().filter { it.value.kind == "CLASS" }.map { (index, a) ->
            corpus.targets.singleOrNull { it.annotationIndex == index }?.also {
                requireInput(it.source.apkSha256 == corpus.apk.sha256 && it.source.descriptor == a.ownerDescriptor && it.manualName == a.name,
                    "Corpus target differs from original annotation")
                requireInput(it.targetId == targetId(corpus.apk.sha256, a.ownerDescriptor), "Corpus target ID changed")
            } ?: throw ValidationException("Class annotation has no target")
        }
        requireInput(targets.size == corpus.targets.size && targets.map { it.targetId }.distinct().size == targets.size, "Invalid corpus target set")
    }

    private fun targetId(sha: String, descriptor: String) = "manual-${Digests.text("$sha\n$descriptor")}"
}
