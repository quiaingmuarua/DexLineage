package dev.dexlineage.rules.recipes

import dev.dexlineage.model.*
import dev.dexlineage.rules.string
import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*

/** Finite descriptor construction shapes, with roles obtained from labels and constructor assignments. */
internal object RpcRecipe {
    private data class Binding(val method: MethodId, val request: String, val response: String, val related: Set<String>, val offset: Int)
    private data class Inspection(val bindings: List<Binding>, val unknown: Boolean, val detail: String)

    fun execute(s: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): List<MatchFact> {
        val service = rule.parameters.string("service")!!; val rpc = rule.parameters.string("rpc")!!
        val methods = if (rule.strategyId == "messages.rpc-message") {
            val ref = dependencies.getValue("descriptor").binding.method!!
            listOfNotNull(s.method(ref))
        } else {
            val first = s.scan.uses[service].orEmpty().map { it.classDescriptor to it.methodDescriptor }.toSet()
            val second = s.scan.uses[rpc].orEmpty().map { it.classDescriptor to it.methodDescriptor }.toSet()
            first.intersect(second).sortedBy { it.first + it.second }.mapNotNull { (owner, short) -> s.methods(owner).singleOrNull { it.id.shortId == short } }
        }
        val result = mutableListOf<MatchFact>()
        for (method in methods) {
            val inspected = inspect(s, rule, method, service, rpc)
            inspected.bindings.forEach { binding ->
                val isMethod = rule.resultKind == EntityKind.METHOD
                val target = if (isMethod) method.id.owner else if (rule.parameters.string("role") == "request") binding.request else binding.response
                result += MessagesRecipes.fact(s, target, MatchStatus.PASS, "rpc-descriptor-role", "Service, RPC and both marshaller roles belong to one descriptor construction",
                    captures = mapOf("service" to service, "rpc" to rpc) + if (isMethod) emptyMap() else mapOf("role" to rule.parameters.string("role")!!),
                    method = if (isMethod) method.id else null,
                    related = (binding.related + method.id.owner).toList(), source = method.id, offset = binding.offset)
            }
            if (inspected.unknown) {
                if (rule.resultKind == EntityKind.METHOD) result += MessagesRecipes.fact(s, method.id.owner, MatchStatus.UNKNOWN, "rpc-descriptor-role", inspected.detail,
                    method = method.id, source = method.id)
                else {
                    // Preserve all possible default-instance types rather than silently excluding an unreadable competitor.
                    val defaults = staticDefaultTypes(s, method)
                    (defaults.ifEmpty { setOf(method.id.owner) }).forEach { target ->
                        result += MessagesRecipes.fact(s, target, MatchStatus.UNKNOWN, "rpc-descriptor-role", inspected.detail,
                            related = listOf(method.id.owner), source = method.id)
                    }
                }
            }
        }
        return result
    }

    private fun inspect(s: DexFactSession, rule: RuleRevision, method: Method, service: String, rpc: String): Inspection {
        val trace = s.trace(method)
        if (!trace.complete) return Inspection(emptyList(), true, trace.reason ?: "Unreadable descriptor construction")
        val nameCalls = trace.calls.filter { call -> call.args == listOf(Value.Text(service), Value.Text(rpc)) && call.method.result == "Ljava/lang/String;" }
        if (nameCalls.isEmpty()) return Inspection(emptyList(), false, "No bound service/RPC invocation")
        val bindings = mutableListOf<Binding>(); var unknown = false
        for (name in nameCalls) {
            val value = Value.Invocation(name.offset, name.method, name.receiver, name.args)
            val nameWrites = trace.writes.filter { it.value == value && it.receiver != null }
            if (nameWrites.isEmpty()) unknown = true
            for (nameWrite in nameWrites) {
                val builder = nameWrite.receiver!!
                val builds = trace.calls.filter { it.offset > nameWrite.offset && it.receiver == builder && it.method.args.isEmpty() && it.method.result in s.classes }
                if (builds.isEmpty()) unknown = true
                for (build in builds) {
                    val builderMethod = s.method(build.method)
                    if (builderMethod == null) { unknown = true; continue }
                    val built = s.trace(builderMethod)
                    if (!built.complete) { unknown = true; continue }
                    val allocations = built.returns.map { it.value }.distinct().filterIsInstance<Value.Allocation>()
                    if (allocations.isEmpty() || built.returns.any { it.value !is Value.Allocation }) unknown = true
                    for (allocation in allocations) {
                        if (allocation.type != build.method.result) { unknown = true; continue }
                        val constructor = built.constructions[allocation]
                        if (constructor == null) { unknown = true; continue }
                        val descriptor = allocation.type
                        val labels = roleFields(s, descriptor, rule)
                        if (labels == null) { unknown = true; continue }
                        val ctor = s.method(constructor.method)
                        if (ctor == null) { unknown = true; continue }
                        val ctorTrace = s.trace(ctor)
                        if (!ctorTrace.complete) { unknown = true; continue }
                        val builderFields = linkedMapOf<String, Field>()
                        for ((role, field) in labels) {
                            val writes = ctorTrace.writes.filter { it.field.key == field.key && it.receiver == Value.Parameter(-1, descriptor) }
                            val params = writes.map { it.value }.distinct()
                            val parameter = params.singleOrNull() as? Value.Parameter
                            val fromBuilder = parameter?.takeIf { it.index >= 0 }?.let { constructor.args.getOrNull(it.index) } as? Value.FieldRead
                            if (fromBuilder == null || fromBuilder.receiver != Value.Parameter(-1, build.method.owner)) { unknown = true; break }
                            builderFields[role] = fromBuilder.field
                        }
                        if (builderFields.size != 3) continue
                        if (builderFields.getValue("name").key != nameWrite.field.key) continue
                        val requestValue = build.fields.entries.singleOrNull { it.key.key == builderFields.getValue("request").key }?.value
                        val responseValue = build.fields.entries.singleOrNull { it.key.key == builderFields.getValue("response").key }?.value
                        val actualName = build.fields.entries.singleOrNull { it.key.key == builderFields.getValue("name").key }?.value
                        if (actualName != value) { if (actualName == null || actualName == Value.Unknown) unknown = true; continue }
                        val requiredFields = builderFields.values.map { it.key }.toSet()
                        if (!stableFields(s, trace, builder, nameWrite.offset, build.offset, requiredFields)) { unknown = true; continue }
                        val req = defaultType(s, requestValue, build.constructions, 1)
                        val res = defaultType(s, responseValue, build.constructions, 1)
                        if (req == null || res == null) { unknown = true; continue }
                        val related = linkedSetOf(descriptor, build.method.owner, constructor.method.owner, name.method.owner, req.first, res.first)
                        related += req.second; related += res.second
                        bindings += Binding(method.id, req.first, res.first, related.filter { it in s.classes }.toSet(), name.offset)
                    }
                }
            }
        }
        return Inspection(bindings.distinct(), unknown, "Descriptor role, constructor transfer or marshaller default instance is outside supported local shapes")
    }

    private fun roleFields(s: DexFactSession, descriptor: String, rule: RuleRevision): Map<String, Field>? {
        val names = mapOf("name" to (rule.parameters.string("nameLabel") ?: "fullMethodName"),
            "request" to (rule.parameters.string("requestLabel") ?: "requestMarshaller"),
            "response" to (rule.parameters.string("responseLabel") ?: "responseMarshaller"))
        val method = s.methods(descriptor).singleOrNull { it.id.name == "toString" && it.id.args.isEmpty() && it.id.result == "Ljava/lang/String;" } ?: return null
        val trace = s.trace(method); if (!trace.complete) return null
        val result = linkedMapOf<String, Field>()
        for ((role, label) in names) {
            val fields = trace.calls.flatMap { call -> call.args.zipWithNext().filter { it.first == Value.Text(label) }.mapNotNull { it.second as? Value.FieldRead } }
                .filter { it.receiver == Value.Parameter(-1, descriptor) && it.field.owner == descriptor }.map { it.field }.distinct()
            if (fields.size != 1) return null
            result[role] = fields.single()
        }
        return result.takeIf { it.values.map { f -> f.key }.distinct().size == 3 }
    }

    /** Unknown calls on the builder must not be assumed to preserve a previously assigned role. */
    private fun stableFields(s: DexFactSession, trace: RawTrace, builder: Value, start: Int, end: Int, fields: Set<String>): Boolean {
        return trace.calls.filter { it.offset > start && it.offset < end && (it.receiver == builder || builder in it.args) }.all { call ->
            if (builder in call.args) return@all false
            val method = s.method(call.method) ?: return@all false
            val body = s.trace(method)
            body.complete && body.writes.none { it.field.key in fields } && body.calls.none { it.receiver == Value.Parameter(-1, call.method.owner) }
        }
    }

    private fun defaultType(s: DexFactSession, value: Value?, constructions: Map<Value, CallEvent>, depth: Int): Pair<String, Set<String>>? {
        when (value) {
            is Value.Allocation -> {
                val constructor = constructions[value] ?: return null
                val defaults = constructor.args.mapNotNull { defaultInstance(s, it) }.distinct()
                return defaults.singleOrNull()?.let { it to setOf(value.type, constructor.method.owner) }
            }
            is Value.Invocation -> {
                if (depth <= 0 || value.receiver != null) return null
                val method = s.method(value.method) ?: return null
                val body = s.trace(method); if (!body.complete) return null
                val allocation = body.returns.map { it.value }.distinct().singleOrNull() as? Value.Allocation ?: return null
                val constructor = body.constructions[allocation] ?: return null
                val supplied = constructor.args.map { argument ->
                    (argument as? Value.Parameter)?.takeIf { it.index >= 0 }?.let { value.args.getOrNull(it.index) } ?: argument
                }
                val defaults = supplied.mapNotNull { defaultInstance(s, it) }.distinct()
                return defaults.singleOrNull()?.let { it to setOf(value.method.owner, allocation.type) }
            }
            else -> return null
        }
    }

    private fun defaultInstance(s: DexFactSession, value: Value): String? {
        val read = value as? Value.FieldRead ?: return null
        if (read.receiver != null || read.field.owner != read.field.type || read.field.owner !in s.classes) return null
        return s.fields(read.field.owner).singleOrNull { it.key == read.field.key && it.flags and 8 != 0 }?.type
    }

    private fun staticDefaultTypes(s: DexFactSession, method: Method): Set<String> {
        val result = linkedSetOf<String>()
        method.code?.visitInstructions { i -> if (i.opcode == jadx.api.plugins.input.insns.Opcode.SGET) {
            i.decode(); val f = i.indexAsField
            if (f.parentClassType == f.type && f.type in s.classes) result += f.type
        } }
        return result
    }
}
