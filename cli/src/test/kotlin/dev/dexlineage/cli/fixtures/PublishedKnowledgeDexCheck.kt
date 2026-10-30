package dev.dexlineage.cli.fixtures

import com.google.gson.GsonBuilder
import dev.dexlineage.model.ClassRef
import dev.dexlineage.model.SCHEMA_VERSION
import dev.dexlineage.model.VersionKnowledge
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

data class PublishedClassFacts(val semanticId: String, val name: String, val clazz: RawDexClass)
data class PublishedAnchorFacts(val key: String, val clazz: RawDexClass, val method: RawDexMethod?)
data class PublishedDexFacts(val knowledgeId: String, val apkSha256: String,
    val entries: List<PublishedClassFacts>, val anchors: List<PublishedAnchorFacts>,
    val unresolvedSemanticIds: List<String>, val elapsedMillis: Long)

/** Consumes published addresses, independently of the rules and evidence that established them. */
object PublishedKnowledgeDexCheck {
    private val gson = GsonBuilder().create()

    fun verify(apk: Path, knowledgeFile: Path): PublishedDexFacts {
        val started = System.nanoTime()
        val knowledge = Files.newBufferedReader(knowledgeFile).use { gson.fromJson(it, VersionKnowledge::class.java) }
        return verify(RawDex.read(apk), knowledge).copy(elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
    }

    internal fun verify(index: RawDexIndex, knowledge: VersionKnowledge): PublishedDexFacts {
        require(knowledge.schemaVersion == SCHEMA_VERSION && knowledge.kind == "version-knowledge") { "Unsupported published knowledge format" }
        require(knowledge.artifact.sha256 == index.apkSha256) { "Published knowledge APK SHA-256 does not match actual APK" }
        require(knowledge.entries.map { it.semanticId }.distinct().size == knowledge.entries.size) { "Duplicate published semantic ID" }
        require(knowledge.anchors.map { it.key }.distinct().size == knowledge.anchors.size) { "Duplicate published anchor key" }
        fun resolve(ref: ClassRef): RawDexClass {
            require(ref.apkSha256 == index.apkSha256) { "Published binding APK SHA-256 does not match actual APK: ${ref.descriptor}" }
            val clazz = requireNotNull(index.classes[ref.descriptor]) { "Published class is absent from actual DEX: ${ref.descriptor}" }
            require(clazz.descriptor == ref.descriptor && clazz.dexEntry == ref.dexEntry) {
                "Published DEX identity does not match actual class: ${ref.dexEntry}:${ref.descriptor}; found ${clazz.dexEntry}:${clazz.descriptor}"
            }
            return clazz
        }
        val entries = knowledge.entries.map { PublishedClassFacts(it.semanticId, it.name, resolve(it.binding)) }
        val anchors = knowledge.anchors.map { anchor ->
            val clazz = resolve(anchor.binding.owner)
            val method = anchor.binding.method?.let { ref ->
                require(ref.owner == anchor.binding.owner) { "Published method anchor owner disagrees with its binding: ${anchor.key}" }
                requireNotNull(clazz.methods.singleOrNull { method ->
                    method.ref.owner == ref.owner.descriptor && method.ref.name == ref.name && method.ref.descriptor == ref.descriptor
                }) { "Published method anchor is absent or not unique in actual DEX: ${anchor.key}: ${ref.owner.descriptor}->${ref.name}${ref.descriptor}" }
            }
            PublishedAnchorFacts(anchor.key, clazz, method)
        }
        // Historical unresolved addresses deliberately remain unconsumed on the current APK.
        return PublishedDexFacts(knowledge.knowledgeId, index.apkSha256, entries, anchors,
            knowledge.unresolved.map { it.entry.semanticId }, 0)
    }
}
