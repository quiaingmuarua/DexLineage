package dev.dexlineage.cli.fixtures

import com.google.gson.GsonBuilder
import jadx.api.plugins.input.insns.Opcode
import java.nio.file.Files
import java.nio.file.Path

/** Checks the compiled test specimen without using production facts, rules, or scenario services. */
object FixturePreflight {
    fun verify(fixtureRoot: Path, casesPath: Path, outputDir: Path) {
        Files.createDirectories(outputDir)
        val checks = mutableListOf<Map<String, Any>>()
        try {
            val manifest = FixtureManifest.read(casesPath)
            val workspace = fixtureRoot.toAbsolutePath().normalize().parent.parent
            val oracles = manifest.versions.mapValues { (_, version) -> R8Oracle(workspace.resolve(version.mapping)) }
            for ((versionId, version) in manifest.versions) {
                val apk = workspace.resolve(version.apk)
                val mapping = workspace.resolve(version.mapping)
                val configuration = workspace.resolve(version.configuration)
                listOf(apk, mapping, configuration).forEach { check(Files.isRegularFile(it)) { "Missing fixture artifact: $it" } }
                val mappingText = Files.readString(mapping)
                check(mappingText.lineSequence().any { it.trim() == "# compiler: R8" }) { "Fixture was not built with R8" }
                check(mappingText.lineSequence().any { it.trim() == "# compiler_version: ${manifest.expectedR8Version}" }) {
                    "Expected R8 ${manifest.expectedR8Version}: $mapping"
                }
                val directives = Files.readString(configuration).lineSequence().map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }.toList()
                check("-dontshrink" in directives && "-dontoptimize" in directives) { "Fixture must preserve code and disable optimization" }
                check(directives.none { it == "-dontobfuscate" }) { "Fixture unexpectedly disables renaming" }
                val raw = RawDex.read(apk).classes
                check(raw.values.all { cls -> cls.sourceFiles.all { it in setOf("fixture", "SourceFile") } }) {
                    "Original SourceFile information survived in fixture or support classes"
                }
                val oracle = oracles.getValue(versionId)
                val logger = oracle.descriptor(manifest.loggerClass)
                val factory = oracle.descriptor(version.factoryClass)
                check(factory != "L${version.factoryClass.replace('.', '/')};") { "Factory class was not renamed" }
                val factoryMethods = oracle.mappedMethods(version.factoryClass, version.factoryMethod)
                check(version.factoryMethod !in factoryMethods) { "Factory method was not renamed" }
                val actualFactory = raw.getValue(factory)
                check(actualFactory.methods.any { it.ref.name in factoryMethods && it.ref.args == listOf("Ljava/lang/String;", "Ljava/lang/String;") && it.ref.result == logger && it.flags and 8 != 0 }) {
                    "Renamed static factory signature was not preserved in DEX"
                }
                val classes = manifest.cases.flatMap { it.versions.getValue(versionId).classes }.associateBy { it.className }
                for ((sourceName, expectation) in classes) {
                    val descriptor = oracle.descriptor(sourceName)
                    check(descriptor != "L${sourceName.replace('.', '/')};") { "Fixture class was not renamed: $sourceName" }
                    val cls = raw[descriptor] ?: error("Mapped fixture class absent from DEX: $sourceName -> $descriptor")
                    for (clue in expectation.methodClues) {
                        val names = oracle.mappedMethods(sourceName, clue.name)
                        val calledNames = oracle.mappedMethods(version.factoryClass, clue.factoryMethod)
                        val methods = cls.methods.filter { it.ref.name in names && it.ref.name !in setOf("<init>", "<clinit>") }
                        check(methods.any { method ->
                            val strings = mutableMapOf<Int, String>()
                            method.instructions.any { insn ->
                                if (insn.opcode == Opcode.CONST_STRING) strings[insn.regs[0]] = insn.literal!!
                                insn.opcode in setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE) &&
                                    insn.method?.let { it.owner == factory && it.name in calledNames && it.args == clue.parameterTypes && it.result == logger } == true &&
                                    insn.regs.take(2).map { strings[it] } == listOf(clue.category, clue.component)
                            }
                        }) { "Method-only decoy disappeared: $sourceName.${clue.name}" }
                        checks += mapOf("version" to versionId, "sourceClass" to sourceName, "methodClue" to clue.name, "component" to clue.component)
                    }
                    for (expected in expectation.loggerFields) {
                        val fieldName = oracle.mappedField(sourceName, expected.name)
                        check(fieldName != expected.name) { "Fixture field was not renamed: $sourceName.${expected.name}" }
                        val field = cls.fields.single { it.name == fieldName }
                        check(field.flags == expected.flags && field.type == logger) { "Field structure changed: $sourceName.${expected.name}: $field" }
                        val names = oracle.mappedMethods(version.factoryClass, expected.factoryMethod)
                        check(expected.factoryMethod !in names) { "Initializer factory was not renamed" }
                        val initializers = cls.methods.filter { it.ref.name == if (expected.flags and 8 != 0) "<clinit>" else "<init>" }
                        val sites = initializers.flatMap { method ->
                            val strings = mutableMapOf<Int, String>()
                            method.instructions.mapIndexedNotNull { index, insn ->
                                when (insn.opcode) {
                                    Opcode.CONST_STRING -> strings[insn.regs[0]] = insn.literal!!
                                    Opcode.MOVE, Opcode.MOVE_OBJECT -> {
                                        val value = strings[insn.regs[1]]
                                        strings.remove(insn.regs[0]); if (value != null) strings[insn.regs[0]] = value
                                    }
                                    Opcode.CONST, Opcode.MOVE_RESULT, Opcode.NEW_INSTANCE -> insn.regs.firstOrNull()?.let(strings::remove)
                                    else -> Unit
                                }
                                if (insn.opcode !in setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE)) return@mapIndexedNotNull null
                                val call = insn.method ?: return@mapIndexedNotNull null
                                if (call.owner != factory || call.name !in names || call.args != expected.parameterTypes || call.result != logger) return@mapIndexedNotNull null
                                if (insn.regs.take(2).map { strings[it] } != listOf(expected.category, expected.component)) return@mapIndexedNotNull null
                                // This fixture deliberately uses direct invoke -> move-result -> field-store bytecode.
                                // Requiring that shape independently catches optimizer/build drift before matching.
                                val move = method.instructions.getOrNull(index + 1) ?: return@mapIndexedNotNull null
                                val put = method.instructions.getOrNull(index + 2) ?: return@mapIndexedNotNull null
                                if (move.opcode != Opcode.MOVE_RESULT || put.opcode != if (expected.flags and 8 != 0) Opcode.SPUT else Opcode.IPUT) return@mapIndexedNotNull null
                                if (put.fieldOwner != descriptor || put.fieldName != fieldName || move.regs.firstOrNull() != put.regs.firstOrNull()) return@mapIndexedNotNull null
                                if (expected.initializer == "complex") check(method.instructions.take(index).any { it.method != null }) { "Complex initializer lost its preceding side effect" }
                                mapOf("sourceClass" to sourceName, "descriptor" to descriptor, "field" to fieldName,
                                    "method" to method.ref.name, "offset" to insn.offset, "flags" to field.flags,
                                    "category" to expected.category, "component" to expected.component, "initializer" to expected.initializer)
                            }
                        }
                        check(sites.size == 1) { "Expected one preserved initializer relation for $sourceName.${expected.name}, found ${sites.size}" }
                        checks += sites.single() + ("version" to versionId)
                    }
                }
                checks += mapOf("version" to versionId, "r8Version" to manifest.expectedR8Version, "dexClasses" to raw.size, "declaredClasses" to classes.size)
            }
            val commonClasses = manifest.cases.flatMap { it.versions.getValue("v1").classes }.map { it.className }.toSet()
                .intersect(manifest.cases.flatMap { it.versions.getValue("v2").classes }.map { it.className }.toSet())
            commonClasses.forEach { name -> check(oracles.getValue("v1").descriptor(name) != oracles.getValue("v2").descriptor(name)) { "Cross-version symbol identity did not change: $name" } }
            write(outputDir, mapOf("schemaVersion" to 1, "status" to "PASS", "checks" to checks, "changedClassIdentities" to commonClasses.size))
        } catch (failure: Exception) {
            write(outputDir, mapOf("schemaVersion" to 1, "status" to "FAIL", "checks" to checks, "error" to (failure.message ?: failure.javaClass.name)))
            throw AssertionError("Fixture build preflight failed: ${failure.message}. See $outputDir/preflight.json", failure)
        }
    }

    private fun write(dir: Path, report: Any) {
        Files.writeString(dir.resolve("preflight.json"), GsonBuilder().setPrettyPrinting().create().toJson(report))
    }

}
