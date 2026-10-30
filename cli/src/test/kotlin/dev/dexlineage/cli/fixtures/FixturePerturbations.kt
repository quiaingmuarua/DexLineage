package dev.dexlineage.cli.fixtures

import com.google.gson.GsonBuilder
import jadx.api.plugins.input.insns.Opcode
import java.nio.file.Files
import java.nio.file.Path

/** Independent specimen checks. These identities and assertions never become matcher input. */
object FixturePerturbations {
    private const val PACKAGE = "dev.dexlineage.fixture.rounds."
    private const val STRING = "Ljava/lang/String;"
    private fun source(type: String) = "L${PACKAGE.replace('.', '/')}$type;"
    private val invokes = setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE,
        Opcode.INVOKE_DIRECT, Opcode.INVOKE_DIRECT_RANGE, Opcode.INVOKE_VIRTUAL,
        Opcode.INVOKE_VIRTUAL_RANGE, Opcode.INVOKE_INTERFACE, Opcode.INVOKE_INTERFACE_RANGE)

    fun verify(fixtureRoot: Path, casesPath: Path, outputDir: Path) {
        Files.createDirectories(outputDir)
        val started = System.nanoTime()
        val checks = mutableListOf<Map<String, Any>>()
        var status = "FAILED"
        var failure: String? = null
        fun record(id: String, action: () -> Map<String, Any>) {
            val at = System.nanoTime()
            try {
                val evidence = action()
                checks += mapOf("id" to id, "status" to "PASS", "elapsedMillis" to millis(at), "evidence" to evidence)
            } catch (error: Exception) {
                checks += mapOf("id" to id, "status" to "FAIL", "elapsedMillis" to millis(at),
                    "error" to (error.message ?: error.javaClass.simpleName))
                throw IllegalStateException("Fixture perturbation failed [$id]: ${error.message}", error)
            }
        }
        try {
            val manifest = FixtureManifest.read(casesPath)
            val workspace = fixtureRoot.toAbsolutePath().normalize().parent.parent
            val versions = manifest.versions.mapValues { (_, version) ->
                Specimen(RawDex.read(workspace.resolve(version.apk)), R8Oracle(workspace.resolve(version.mapping)))
            }
            val first = versions.getValue("v1")
            val second = versions.getValue("v2")
            record("renaming-keeps-version-identities-distinct") {
                val names = listOf("RoundLogger", "LoggerBusiness", "NamedHandler", "Descriptor", "DescriptorBuilder",
                    "RequestRecord", "ResponseRecord", "RecordMarshaller")
                val identities = names.associateWith { type -> versions.mapValues { (_, specimen) -> specimen.cls(type).descriptor } }
                identities.forEach { (name, ids) ->
                    check(ids.values.toSet().size == 2 && ids.values.none { it == source(name) }) { "No real cross-version rename for $name" }
                }
                mapOf("classes" to identities, "apkSha256" to versions.mapValues { it.value.raw.apkSha256 })
            }
            for ((version, specimen) in versions) {
                record("$version-stable-logger-locating-facts") { verifyLogger(specimen, version) }
                record("$version-stable-handler-role") { verifyHandler(specimen) }
                record("$version-rpc-role-order-and-construction") { verifyRpc(specimen, version) }
            }
            record("v2-irrelevant-members-and-overloads-survive-r8") {
                check(first.cls("RoundLogger").fields.size == 2)
                check(second.cls("RoundLogger").fields.size == 3)
                check(first.cls("LoggerBusiness").fields.size == 1)
                check(second.cls("LoggerBusiness").fields.size == 2)
                check(first.cls("NamedHandler").fields.isEmpty())
                check(second.cls("NamedHandler").fields.size == 1)
                val fields = listOf(second.field("RoundLogger", "diagnosticSequence", "J"),
                    second.field("LoggerBusiness", "inspectionCount", "I"), second.field("NamedHandler", "inspectionSequence", "J"))
                fields.forEach { field ->
                    val actual = second.raw.classes.getValue(field.owner).fields.single { it.name == field.name && it.type == field.type }
                    check(actual.flags and 2 != 0 && actual.flags and 8 == 0) { "Noise field must stay private instance state" }
                }
                val overloads = listOf(
                    second.method("RoundLogger", "construct", "($STRING${STRING}I)${source("RoundLogger")}"),
                    second.method("LoggerBusiness", "describe", "(I)$STRING"),
                    second.method("NamedHandler", "componentName", "(I)$STRING"),
                    second.method("NamedHandler", "requestId", "(J)$STRING"))
                check(overloads.all { it.ref.args.isNotEmpty() })
                second.method("RoundLogger", "nextDiagnosticSequence", "()J")
                second.method("NamedHandler", "describe", "()$STRING")
                mapOf("fields" to fields, "overloads" to overloads.map { it.ref })
            }
            record("non-locating-describe-body-changes-to-helper") {
                val old = first.method("LoggerBusiness", "describe", "()$STRING")
                val updated = second.method("LoggerBusiness", "describe", "()$STRING")
                check(old.instructions.none { it.opcode in invokes }) { "v1 describe unexpectedly calls a helper" }
                val helper = second.method("LoggerDescription", "render", "(${STRING}I)$STRING").ref
                check(updated.instructions.count { it.method == helper && it.opcode in invokes } == 1)
                val oldComponent = first.field("RoundLogger", "component", STRING)
                val newComponent = second.field("RoundLogger", "component", STRING)
                check(old.instructions.any { it.isField(oldComponent, Opcode.IGET) })
                check(updated.instructions.any { it.isField(newComponent, Opcode.IGET) })
                val handlerHelper = second.method("HandlerDescription", "render", "(J)$STRING").ref
                val handlerDescribe = second.method("NamedHandler", "describe", "()$STRING")
                check(handlerDescribe.instructions.any { it.method == handlerHelper && it.opcode in invokes })
                mapOf("v1" to old.ref, "v2" to updated.ref, "helper" to helper, "handlerHelper" to handlerHelper)
            }
            status = "PASS"
        } catch (error: Exception) {
            failure = error.message ?: error.javaClass.name
            throw error
        } finally {
            val report = mapOf("schemaVersion" to 1, "kind" to "raw-dex-fixture-perturbations", "status" to status,
                "elapsedMillis" to millis(started), "checks" to checks, "error" to failure)
            Files.writeString(outputDir.resolve("perturbations.json"), GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n")
        }
    }

    private fun verifyLogger(s: Specimen, version: String): Map<String, Any> {
        val method = if (version == "v1") "create" else "construct"
        val factory = s.method("RoundLogger", method, "($STRING$STRING)${source("RoundLogger")}")
        check(factory.flags and 8 != 0)
        check(s.cls("RoundLogger").methods.count { it.flags and 8 != 0 && it.ref.args == listOf(STRING, STRING) && it.ref.result == s.cls("RoundLogger").descriptor } == 1) {
            "Noise introduced a same-signature factory competitor"
        }
        val field = s.field("LoggerBusiness", "LOGGER", source("RoundLogger"))
        val actual = s.cls("LoggerBusiness").fields.single { it.name == field.name }
        check(actual.type == s.cls("RoundLogger").descriptor && actual.flags and (2 or 8 or 16) == (2 or 8 or 16))
        val initializer = s.cls("LoggerBusiness").methods.single { it.ref.name == "<clinit>" }
        val site = initializer.instructions.indexOfFirst { it.method == factory.ref }
        check(site >= 0)
        val call = initializer.instructions[site]
        check(call.opcode in setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE))
        val strings = stringsBefore(initializer.instructions, site)
        val tag = if (version == "v1") "OldRoundScope" else "NewRoundScope"
        check(call.regs.map { strings[it] } == listOf(tag, "RoundCache"))
        val move = initializer.instructions.getOrNull(site + 1)
        val store = initializer.instructions.getOrNull(site + 2)
        check(move?.opcode == Opcode.MOVE_RESULT && store != null && store.isField(field, Opcode.SPUT) && store.regs.first() == move.regs.first()) {
            "Logger initialization no longer has the declared call-result-field relationship"
        }
        return mapOf("factory" to factory.ref, "field" to field, "tag" to tag, "component" to "RoundCache", "callOffset" to call.offset)
    }

    private fun verifyHandler(s: Specimen): Map<String, Any> {
        val component = s.method("NamedHandler", "componentName", "()$STRING")
        val request = s.method("NamedHandler", "requestId", "()$STRING")
        check(constantReturns(component) == listOf("RoundHandler"))
        check(constantReturns(request) == listOf("round-request"))
        check(component.ref != request.ref)
        return mapOf("componentMethod" to component.ref, "requestMethod" to request.ref,
            "component" to "RoundHandler", "requestId" to "round-request")
    }

    private fun verifyRpc(s: Specimen, version: String): Map<String, Any> {
        val request = s.field("Descriptor", "request", source("WireMarshaller"))
        val response = s.field("Descriptor", "response", source("WireMarshaller"))
        val name = s.field("Descriptor", "fullName", STRING)
        val orderedFields = if (version == "v1") listOf(request, response, name) else listOf(name, response, request)
        val sourceArgs = if (version == "v1") listOf(source("WireMarshaller"), source("WireMarshaller"), STRING)
            else listOf(STRING, source("WireMarshaller"), source("WireMarshaller"))
        val constructor = s.method("Descriptor", "<init>", sourceArgs.joinToString("", "(", ")V"))
        val receiver = constructor.instructions.single { it.method?.owner == "Ljava/lang/Object;" && it.method.name == "<init>" }.regs.single()
        val stores = constructor.instructions.filter { insn -> orderedFields.any { insn.isField(it, Opcode.IPUT) } }
        check(stores.map { it.fieldName } == orderedFields.map { it.name }) { "Descriptor role assignment order did not change as declared" }
        stores.forEachIndexed { i, insn -> check(insn.regs == listOf(receiver + 1 + i, receiver)) { "Wrong descriptor constructor role parameter" } }

        val build = s.method("DescriptorBuilder", "build", "()${source("Descriptor")}")
        val callIndex = build.instructions.indexOfFirst { it.method == constructor.ref }
        check(callIndex >= 0)
        val builderFields = orderedFields.map { field ->
            val sourceName = when (field) { request -> "request"; response -> "response"; else -> "fullName" }
            s.field("DescriptorBuilder", sourceName, if (sourceName == "fullName") STRING else source("WireMarshaller"))
        }
        val buildCall = build.instructions[callIndex]
        check(buildCall.regs.size == 4)
        buildCall.regs.drop(1).forEachIndexed { i, reg ->
            val read = build.instructions.take(callIndex).lastOrNull { it.opcode == Opcode.IGET && it.regs.first() == reg }
            check(read != null && read.isField(builderFields[i], Opcode.IGET)) { "Builder passes wrong semantic role to descriptor constructor" }
        }
        val text = s.method("Descriptor", "toString", "()$STRING")
        val expectedLabels = if (version == "v1") listOf("fullMethodName", "requestMarshaller", "responseMarshaller")
            else listOf("responseMarshaller", "fullMethodName", "requestMarshaller")
        val labelInstructions = text.instructions.filter { it.opcode == Opcode.CONST_STRING && it.literal in expectedLabels }
        check(labelInstructions.map { it.literal } == expectedLabels) { "Descriptor label presentation did not change as declared" }
        val put = s.method("Description", "put", "(${STRING}Ljava/lang/Object;)${source("Description")}").ref
        val labelFields = mapOf("fullMethodName" to name, "requestMarshaller" to request, "responseMarshaller" to response)
        for (i in text.instructions.indices.filter { text.instructions[it].method == put }) {
            val call = text.instructions[i]
            val label = stringsBefore(text.instructions, i)[call.regs[1]] ?: error("Missing descriptor label")
            val read = text.instructions.take(i).lastOrNull { it.opcode == Opcode.IGET && it.regs.first() == call.regs[2] }
            check(read != null && read.isField(labelFields.getValue(label), Opcode.IGET)) { "Label is bound to the wrong role field" }
        }
        check(text.instructions.count { it.method == put } == 3)

        val location = if (version == "v1") "RpcDescriptors" else "RpcStub"
        val read = s.method(location, "read", "()${source("Descriptor")}")
        val nameCall = s.method("Descriptor", "fullName", "($STRING$STRING)$STRING").ref
        val nameIndex = read.instructions.indexOfFirst { it.method == nameCall }
        check(nameIndex >= 0)
        check(read.instructions[nameIndex].regs.map { stringsBefore(read.instructions, nameIndex)[it] } == listOf("fixture.Sample", "ReadRecord"))
        val wrap = s.method("RecordMarshallers", "wrap", "(${source("RecordValue")})${source("WireMarshaller")}").ref
        val marshal = s.method("RecordMarshaller", "<init>", "(${source("RecordValue")})V").ref
        check(read.instructions.count { it.method == wrap } == if (version == "v1") 2 else 0)
        check(read.instructions.count { it.method == marshal } == if (version == "v2") 2 else 0)
        for ((role, record) in listOf("request" to "RequestRecord", "response" to "ResponseRecord")) {
            val defaultValue = s.field(record, "DEFAULT", source(record))
            val destination = s.field("DescriptorBuilder", role, source("WireMarshaller"))
            val getIndex = read.instructions.indexOfFirst { it.isField(defaultValue, Opcode.SGET) }
            check(getIndex >= 0)
            val defaultReg = read.instructions[getIndex].regs.single()
            val marshalIndex = read.instructions.indices.firstOrNull { i -> i > getIndex &&
                read.instructions[i].method == (if (version == "v1") wrap else marshal) &&
                read.instructions[i].regs.last() == defaultReg } ?: error("Missing $role default-instance marshaller")
            val resultReg: Int
            val storeIndex: Int
            if (version == "v1") {
                val move = read.instructions[marshalIndex + 1]
                check(move.opcode == Opcode.MOVE_RESULT)
                resultReg = move.regs.single()
                storeIndex = marshalIndex + 2
            } else {
                resultReg = read.instructions[marshalIndex].regs.first()
                storeIndex = marshalIndex + 1
            }
            val store = read.instructions[storeIndex]
            check(store.isField(destination, Opcode.IPUT) && store.regs.first() == resultReg) {
                "The $record default instance no longer feeds the $role field"
            }
        }
        val roleStoreOrder = read.instructions.filter { it.opcode == Opcode.IPUT && it.fieldOwner == s.cls("DescriptorBuilder").descriptor }
        val expectedStoreOrder = listOf("fullName") + if (version == "v1") listOf("request", "response") else listOf("response", "request")
        check(roleStoreOrder.map { it.fieldName } == expectedStoreOrder.map { s.field("DescriptorBuilder", it, if (it == "fullName") STRING else source("WireMarshaller")).name })
        check(read.instructions.count { it.method == build.ref } == 1)
        check(roleStoreOrder.map { it.regs[1] }.distinct().size == 1) { "Positive RPC fixture no longer assigns the same builder" }
        check(read.instructions.single { it.method == build.ref }.regs.single() == roleStoreOrder.first().regs[1]) {
            "The descriptor is built from a different builder than the role assignments"
        }
        return mapOf("method" to read.ref, "constructor" to constructor.ref, "constructorFields" to orderedFields,
            "builderReads" to builderFields, "toStringLabels" to expectedLabels, "builderAssignmentOrder" to expectedStoreOrder,
            "marshallerShape" to if (version == "v1") "static-wrapper" else "direct-constructor")
    }

    private fun constantReturns(method: RawDexMethod): List<String?> = method.instructions.mapIndexedNotNull { i, insn ->
        if (insn.opcode == Opcode.RETURN) listOf(stringsBefore(method.instructions, i)[insn.regs.single()]) else null
    }.flatten()

    private fun stringsBefore(instructions: List<RawDexInstruction>, end: Int): Map<Int, String> {
        val strings = mutableMapOf<Int, String>()
        instructions.take(end).forEach { insn ->
            when (insn.opcode) {
                Opcode.CONST_STRING -> strings[insn.regs.first()] = requireNotNull(insn.literal)
                Opcode.MOVE, Opcode.MOVE_OBJECT -> {
                    val value = strings[insn.regs[1]]
                    strings.remove(insn.regs.first())
                    if (value != null) strings[insn.regs.first()] = value
                }
                Opcode.MOVE_RESULT, Opcode.CONST, Opcode.IGET, Opcode.SGET, Opcode.NEW_INSTANCE -> insn.regs.firstOrNull()?.let(strings::remove)
                else -> Unit
            }
        }
        return strings
    }

    private fun RawDexInstruction.isField(field: RawDexFieldRef, operation: Opcode) =
        opcode == operation && fieldOwner == field.owner && fieldName == field.name && fieldType == field.type

    private class Specimen(val raw: RawDexIndex, val oracle: R8Oracle) {
        fun cls(name: String) = raw.classes.getValue(oracle.descriptor(PACKAGE + name))
        fun method(owner: String, name: String, descriptor: String): RawDexMethod {
            val ref = oracle.method(PACKAGE + owner, name, descriptor)
            check(name.startsWith("<") || name == "toString" || ref.name != name) { "Fixture method was not renamed: $owner.$name$descriptor" }
            return raw.classes.getValue(ref.owner).methods.single { it.ref == ref }
        }
        fun field(owner: String, name: String, type: String): RawDexFieldRef {
            val ref = oracle.field(PACKAGE + owner, name, type)
            check(ref.name != name) { "Fixture field was not renamed: $owner.$name" }
            check(raw.classes.getValue(ref.owner).fields.any { it.name == ref.name && it.type == ref.type })
            return ref
        }
    }

    private fun millis(start: Long) = (System.nanoTime() - start) / 1_000_000
}
