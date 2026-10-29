package dev.dexlineage.cli.fixtures

import com.google.gson.GsonBuilder
import net.fabricmc.mappingio.MappingReader
import net.fabricmc.mappingio.format.MappingFormat
import net.fabricmc.mappingio.tree.MemoryMappingTree
import java.io.StringReader
import java.nio.file.Files
import java.nio.file.Path

/** Source-authored expectations; this data is never sent to the production matcher. */
data class FixtureVersion(val tag: String, val factoryClass: String, val factoryMethod: String,
    val apk: String, val mapping: String, val configuration: String)
data class FixtureLoggerField(val name: String, val flags: Int, val initializer: String,
    val factoryMethod: String, val parameterTypes: List<String>, val category: String, val component: String)
data class FixtureMethodClue(val name: String, val factoryMethod: String, val parameterTypes: List<String>,
    val category: String, val component: String)
data class FixtureClass(val className: String, val loggerFields: List<FixtureLoggerField>, val methodClues: List<FixtureMethodClue>)
data class FixtureCaseVersion(val resolution: String, val owners: List<String>, val discoveryOwners: List<String>,
    val classes: List<FixtureClass>)
data class FixtureCase(val id: String, val component: String, val semanticAlias: String,
    val versions: Map<String, FixtureCaseVersion>)
data class FixtureManifest(val schemaVersion: Int, val packagePrefix: String, val expectedR8Version: String,
    val loggerClass: String, val versions: Map<String, FixtureVersion>, val cases: List<FixtureCase>) {
    companion object {
        private val gson = GsonBuilder().create()
        fun read(path: Path): FixtureManifest = Files.newBufferedReader(path).use { reader ->
            gson.fromJson(reader, FixtureManifest::class.java).also { value ->
                require(value.schemaVersion == 1) { "Unsupported fixture contract" }
                require(value.versions.keys == setOf("v1", "v2")) { "Fixture needs exactly v1 and v2" }
                require(value.cases.isNotEmpty() && value.cases.map { it.id }.distinct().size == value.cases.size)
                require(value.cases.map { it.component }.distinct().size == value.cases.size) { "Each scenario needs its own component literal" }
                value.cases.forEach { require(it.versions.keys == value.versions.keys) }
            }
        }
    }
}

/** Independent original-source -> R8 identity oracle, available only on the test classpath. */
class R8Oracle(path: Path) {
    val tree = MemoryMappingTree()
    init {
        require(Files.isRegularFile(path)) { "Missing R8 mapping: $path" }
        // mapping-io 0.6.1 treats source-line suffixes as inline records and skips them.
        // The fixture disables optimization/inlining; strip only source line numbers for this
        // test-side parse, preserving all names, signatures and the original mapping artifact.
        val memberNames = Files.readString(path).replace(Regex("(?<=\\)):\\d+(?::\\d+)?(?= -> )"), "")
        MappingReader.read(StringReader(memberNames), MappingFormat.PROGUARD_FILE, tree)
        require(tree.dstNamespaces.size == 1) { "Expected one obfuscated namespace in $path" }
    }
    fun mappedClass(sourceName: String): String = tree.getClass(sourceName.replace('.', '/'))?.getDstName(0)
        ?: error("Source class absent from independent R8 oracle: $sourceName")
    fun descriptor(sourceName: String): String = "L${mappedClass(sourceName)};"
    fun originalName(descriptor: String): String? = tree.classes.singleOrNull { "L${it.getDstName(0)};" == descriptor }?.srcName?.replace('/', '.')
    fun mappedField(sourceClass: String, sourceName: String): String {
        val cls = tree.getClass(sourceClass.replace('.', '/')) ?: error("Missing source class $sourceClass")
        return cls.fields.singleOrNull { it.srcName == sourceName }?.getDstName(0)
            ?: error("Missing/unmapped source field $sourceClass.$sourceName")
    }
    fun mappedMethods(sourceClass: String, sourceName: String): Set<String> {
        val cls = tree.getClass(sourceClass.replace('.', '/')) ?: error("Missing source class $sourceClass")
        return cls.methods.filter { it.srcName == sourceName }.mapNotNull { it.getDstName(0) }.toSet()
            .also { require(it.isNotEmpty()) { "Missing mapped method $sourceClass.$sourceName" } }
    }
}
