package dev.dexlineage.rules

import dev.dexlineage.apk.ApkReader
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import jadx.api.JavaClass
import jadx.api.JadxArgs
import jadx.api.JadxDecompiler
import jadx.api.plugins.JadxPlugin
import jadx.api.plugins.input.data.attributes.JadxAttrType
import jadx.api.plugins.loader.JadxPluginLoader
import jadx.core.dex.attributes.AType
import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.ConstClassNode
import jadx.core.dex.instructions.InsnType
import jadx.core.dex.instructions.InvokeNode
import jadx.core.dex.instructions.args.ArgType
import jadx.core.dex.instructions.args.InsnArg
import jadx.core.dex.instructions.args.InsnWrapArg
import jadx.core.dex.instructions.args.LiteralArg
import jadx.core.dex.nodes.InsnNode
import jadx.plugins.input.dex.DexInputPlugin
import java.nio.file.Files
import java.nio.file.Path

/** Reads one APK in one JADX session. No naming semantics are assigned here. */
internal object FieldFactsReader {
    private data class RawField(val name: String, val type: String, val flags: Int)

    fun read(artifact: Artifact, owners: Set<String>, inventory: Map<String, String>, workDir: Path,
             factoryNeeded: (FieldBinding) -> Boolean): FieldAnalysis {
        val started = System.nanoTime()
        if (owners.isEmpty()) return FieldAnalysis(emptyList(), emptyList(), emptyList(), 0)
        Files.createDirectories(workDir)
        val config = JadxArgs().apply {
            inputFiles = emptyList()
            isSkipResources = true
            isSkipFilesSave = true
            outDir = workDir.toAbsolutePath().toFile()
            threadsCount = 2
            isDeobfuscationOn = false
            isUseSourceNameAsClassAlias = false
            isRespectBytecodeAccModifiers = true
            // Facts must retain literal arguments and the original initializer call.
            isReplaceConsts = false
            isInlineMethods = false
            renameFlags = emptySet()
            pluginLoader = object : JadxPluginLoader {
                override fun load(): List<JadxPlugin> = listOf(DexInputPlugin())
                override fun close() = Unit
            }
        }
        val bindings = mutableListOf<FieldBinding>()
        val code = sortedMapOf<String, DecompiledClass>()
        val diagnostics = mutableListOf<String>()
        val unknownOwners = sortedSetOf<String>()
        try {
            JadxDecompiler(config).use { jadx ->
                jadx.addCustomCodeLoader(DexInputPlugin().loadFiles(listOf(Path.of(artifact.path))))
                jadx.load()
                val loadErrors = jadx.errorsCount
                fun resolve(descriptor: String): JavaClass? {
                    val raw = Identities.rawName(descriptor)
                    return jadx.searchJavaClassByOrigFullName(raw)?.also {
                        if (it.rawName != raw) throw ExecutionException("Resolved a different original class for $descriptor")
                    }
                }
                fun readCode(descriptor: String, cls: JavaClass): DecompiledClass {
                    code[descriptor]?.let { return it }
                    val began = System.nanoTime()
                    val beforeErrors = jadx.errorsCount
                    val beforeWarnings = jadx.warnsCount
                    val notes = mutableListOf<String>()
                    if (loadErrors != 0) notes += "JADX load recorded $loadErrors errors"
                    val java = try { cls.code } catch (e: Exception) { notes += "Java decompilation failed: ${e.message}"; "" }
                    notes += ApkReader.codeDiagnostics(java, jadx.errorsCount - beforeErrors, jadx.warnsCount - beforeWarnings)
                    val smali = if (notes.isNotEmpty()) try { cls.smali } catch (e: Exception) { notes += "Smali retrieval failed: ${e.message}"; null } else null
                    return DecompiledClass(descriptor, java, smali, notes.isNotEmpty(), notes, elapsed(began)).also { code[descriptor] = it }
                }
                for (descriptor in owners.sorted()) {
                    val ref = ClassRef(artifact.sha256, descriptor, inventory.getValue(descriptor))
                    val cls = resolve(descriptor)
                    if (cls == null) {
                        diagnostics += "$descriptor: JADX could not resolve original class"
                        unknownOwners += descriptor
                        continue
                    }
                    val raw = mutableListOf<RawField>()
                    try {
                        cls.classNode.clsData.visitFieldsAndMethods({ f -> raw += RawField(f.name, f.type, f.accessFlags) }, {})
                    } catch (e: Exception) {
                        diagnostics += "$descriptor: Original field metadata unavailable: ${e.message}"
                        unknownOwners += descriptor
                    }
                    val material = readCode(descriptor, cls)
                    val nodes = cls.classNode.fields.associateBy { it.fieldInfo.name to typeDescriptor(it.fieldInfo.type) }
                    for (field in raw.sortedWith(compareBy({ it.name }, { it.type }))) {
                        val node = nodes[field.name to field.type]
                        if (node == null) {
                            bindings += FieldBinding(ref, field.name, field.type, field.flags, null, null, null, "Original field not represented in JADX model")
                            continue
                        }
                        val init = node.get(AType.FIELD_INIT_INSN)
                        if (init == null) {
                            val reason = if (node.contains(JadxAttrType.CONSTANT_VALUE)) null else "No extracted initializer expression"
                            bindings += FieldBinding(ref, field.name, field.type, field.flags, null, null, null, reason)
                            continue
                        }
                        val invocation = init.insn as? InvokeNode
                        val assignedOwner = typeDescriptor(node.fieldInfo.declClass.type)
                        if (invocation == null) {
                            bindings += FieldBinding(ref, field.name, field.type, field.flags, init.insnMth.methodInfo.shortId, null, assignedOwner,
                                unsupportedInitializerReason(init.insn))
                            continue
                        }
                        val method = invocation.callMth
                        val first = invocation.firstArgOffset
                        val callArgs = (first until invocation.argsCount).map { invocation.getArg(it) }
                        val arguments = callArgs.map(::stringConstant)
                        val nonStrings = callArgs.indices.filter { knownNonStringConstant(callArgs[it]) }.toSet()
                        val call = CallFact(typeDescriptor(method.declClass.type), method.name, method.argumentsTypes.map(::typeDescriptor),
                            typeDescriptor(method.returnType), invocation.invokeType.name, arguments, invocation.offset.takeIf { it >= 0 }, nonStrings)
                        bindings += FieldBinding(ref, field.name, field.type, field.flags, init.insnMth.methodInfo.shortId, call, assignedOwner)
                    }
                    if (raw.isEmpty() && material.javaCode.isBlank()) diagnostics += "$descriptor: No readable code or field structure"
                }
                val factories = bindings.filter(factoryNeeded).mapNotNull { it.call?.declaringType }
                    .filter { it in inventory && it !in code }.toSortedSet()
                for (descriptor in factories) {
                    val cls = resolve(descriptor)
                    if (cls == null) diagnostics += "$descriptor: Factory class could not be resolved"
                    else readCode(descriptor, cls)
                }
            }
        } catch (e: Exception) {
            if (e is ValidationException || e is ExecutionException) throw e
            throw ExecutionException("Cannot read field initializer facts from ${artifact.path}: ${e.message}", e)
        }
        Digests.verify(artifact)
        return FieldAnalysis(bindings.sortedWith(compareBy({ it.owner.descriptor }, { it.fieldName }, { it.fieldType })), code.values.toList(), diagnostics, elapsed(started), unknownOwners)
    }

    private fun stringConstant(arg: InsnArg): String? = ((arg as? InsnWrapArg)?.wrapInsn as? ConstStringNode)?.string
    internal fun unsupportedInitializerReason(insn: InsnNode): String? {
        // A wrapper or branch can contain a call we cannot bind reliably; absence of a direct
        // InvokeNode is only a known mismatch when the initializer is a constant expression.
        if (insn is ConstStringNode || insn is ConstClassNode || isLiteralConstant(insn)) return null
        return "Initializer expression ${insn.type} is not supported as a direct method invocation"
    }

    internal fun knownNonStringConstant(arg: InsnArg): Boolean {
        if (arg is LiteralArg) return true
        val insn = (arg as? InsnWrapArg)?.wrapInsn ?: return false
        return insn is ConstClassNode || isLiteralConstant(insn)
    }
    private fun isLiteralConstant(insn: InsnNode) = insn.type == InsnType.CONST && insn.argsCount == 1 && insn.getArg(0) is LiteralArg
    private fun typeDescriptor(type: ArgType): String = when {
        type.isArray -> "[" + typeDescriptor(type.arrayElement)
        type.isPrimitive -> type.primitiveType.shortName
        type.isObject -> "L${type.`object`.replace('.', '/')};"
        else -> "?"
    }
    private fun elapsed(started: Long) = (System.nanoTime() - started) / 1_000_000
}
