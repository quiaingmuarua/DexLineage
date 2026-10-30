package dev.dexlineage.mapping

import dev.dexlineage.io.ExecutionException
import dev.dexlineage.io.Identities
import dev.dexlineage.io.requireInput
import dev.dexlineage.model.AcceptedRename
import dev.dexlineage.model.VerifiedRename
import jadx.api.JadxArgs
import jadx.api.JadxDecompiler
import jadx.api.args.UserRenamesMappingsMode
import jadx.api.plugins.JadxPlugin
import jadx.api.plugins.loader.JadxPluginLoader
import jadx.plugins.input.dex.DexInputPlugin
import jadx.plugins.mappings.RenameMappingsPlugin
import net.fabricmc.mappingio.MappedElementKind
import net.fabricmc.mappingio.MappingReader
import net.fabricmc.mappingio.MappingWriter
import net.fabricmc.mappingio.format.MappingFormat
import net.fabricmc.mappingio.tree.MemoryMappingTree
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** Tiny v2 is an output boundary: the migration model always retains DEX descriptors. */
object MappingOutput {
    fun write(path: Path, renames: List<AcceptedRename>) {
        val sorted = validatedRenames(renames)
        requireInput(!Files.exists(path), "Mapping file already exists: $path")
        Files.newBufferedWriter(path, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW).use { text ->
            val mappingWriter = MappingWriter.create(text, MappingFormat.TINY_2_FILE)
                ?: throw ExecutionException("mapping-io does not support Tiny v2 output")
            mappingWriter.use { writer ->
                if (writer.visitHeader()) writer.visitNamespaces("obfuscated", listOf("named"))
                if (writer.visitContent()) {
                    for (rename in sorted) {
                        if (writer.visitClass(internalName(rename.descriptor))) {
                            writer.visitDstName(MappedElementKind.CLASS, 0, rename.newFullName.replace('.', '/'))
                            writer.visitElementContent(MappedElementKind.CLASS)
                        }
                    }
                }
                writer.visitEnd()
            }
        }
    }

    /** Reload a generated mapping in a separate, DEX-only JADX instance. Never saves an APK/project. */
    fun verify(apk: Path, mapping: Path, renames: List<AcceptedRename>, workDir: Path): List<VerifiedRename> {
        val sorted = validatedRenames(renames)
        requireInput(Files.isRegularFile(apk), "APK not found: $apk")
        requireInput(Files.isRegularFile(mapping), "Mapping not found: $mapping")
        verifyContents(mapping, sorted)
        if (sorted.isEmpty()) return emptyList()

        Files.createDirectories(workDir)
        val args = JadxArgs().apply {
            inputFiles = emptyList()
            isSkipResources = true
            isSkipFilesSave = true
            outDir = workDir.toAbsolutePath().resolve("jadx-output").toFile()
            threadsCount = 2
            isDeobfuscationOn = false
            isUseSourceNameAsClassAlias = false
            renameFlags = emptySet()
            userRenamesMappingsPath = mapping.toAbsolutePath()
            userRenamesMappingsMode = UserRenamesMappingsMode.READ
            pluginOptions = mapOf("rename-mappings.format" to "TINY_2_FILE")
            // The normal plugin discovery can initialize unrelated GUI/script caches.
            pluginLoader = object : JadxPluginLoader {
                override fun load(): List<JadxPlugin> = listOf(DexInputPlugin(), RenameMappingsPlugin())
                override fun close() = Unit
            }
        }
        return JadxDecompiler(args).use { decompiler ->
            decompiler.addCustomCodeLoader(DexInputPlugin().loadFiles(listOf(apk.toAbsolutePath())))
            decompiler.load()
            sorted.map { rename ->
                val rawName = Identities.rawName(rename.descriptor)
                val cls = decompiler.searchJavaClassByOrigFullName(rawName)
                    ?: throw ExecutionException("Mapping verification could not find original class: ${rename.descriptor}")
                val code = cls.code
                if (cls.rawName != rawName) {
                    throw ExecutionException("Mapping changed original class identity: ${rename.descriptor}")
                }
                if (cls.fullName != rename.newFullName) {
                    throw ExecutionException("Mapping not applied for ${rename.descriptor}: expected ${rename.newFullName}, got ${cls.fullName}")
                }
                val declaration = Regex("(?:class|interface|enum|record)\\s+${Regex.escape(cls.name)}(?=[\\s<{(])")
                if (!declaration.containsMatchIn(code)) {
                    throw ExecutionException("Mapped class declaration absent from generated code: ${rename.descriptor}")
                }
                VerifiedRename(rename.descriptor, cls.rawName, cls.fullName)
            }
        }
    }

    fun verifyContents(mapping: Path, renames: List<AcceptedRename>) {
        requireInput(MappingReader.detectFormat(mapping) == MappingFormat.TINY_2_FILE, "Expected Tiny v2 Mapping: $mapping")
        val tree = MemoryMappingTree()
        MappingReader.read(mapping, MappingFormat.TINY_2_FILE, tree)
        requireInput(tree.srcNamespace == "obfuscated" && tree.dstNamespaces == listOf("named"), "Expected only obfuscated -> named namespaces")
        requireInput(tree.classes.all { it.fields.isEmpty() && it.methods.isEmpty() }, "Class-only mapping contains member records")
        val actual = tree.classes.associate { it.srcName to it.getDstName(0) }
        val expected = renames.associate { internalName(it.descriptor) to it.newFullName.replace('.', '/') }
        requireInput(actual == expected, "Mapping entries do not match accepted class renames")
    }

    private fun validatedRenames(renames: List<AcceptedRename>): List<AcceptedRename> {
        for (rename in renames) {
            Identities.requireDescriptor(rename.descriptor)
            requireInput(rename.newFullName.isNotEmpty(), "Empty target class name")
            rename.newFullName.split('.').forEach { Identities.renamedFullName("Lplaceholder;", it) }
        }
        requireInput(renames.map { it.descriptor }.distinct().size == renames.size, "Duplicate source class in accepted mappings")
        requireInput(renames.map { it.newFullName }.distinct().size == renames.size, "Duplicate target name in accepted mappings")
        return renames.sortedBy { it.descriptor }
    }

    private fun internalName(descriptor: String): String = descriptor.substring(1, descriptor.length - 1)
}
