package dev.dexlineage.messages

import dev.dexlineage.model.*
import dev.dexlineage.io.ExecutionException
import dev.dexlineage.rules.string
import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*

/** Finite descriptor construction shapes, with roles obtained from labels and constructor assignments. */
internal object RpcRecipe {
    internal data class Binding(val method: MethodId, val request: String, val response: String,
        val descriptorType: String, val builderType: String,
        val requestDeclarationType: String, val responseDeclarationType: String,
        val requestImplementationType: String, val responseImplementationType: String,
        val related: Set<String>, val offset: Int)
    internal data class Inspection(val bindings: List<Binding>, val unknown: Boolean, val detail: String)
    private data class Marshaller(val messageType: String, val implementationType: String, val related: Set<String>)
    internal data class RelatedType(val type: String, val status: MatchStatus, val binding: Binding, val detail: String)

    fun execute(s: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): List<MatchFact> {
        if (rule.strategyId == "messages.rpc-related-type") return relatedTypes(s, rule, dependencies.getValue("descriptor"))
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

    private fun relatedTypes(s: DexFactSession, rule: RuleRevision, anchor: SupportAnchor): List<MatchFact> {
        // The producer's immutable rule is the only authority for service/RPC and effective labels.
        val producer = anchor.rule
        val service = producer.parameters.string("service")!!
        val rpc = producer.parameters.string("rpc")!!
        val method = s.method(anchor.binding.method!!) ?: throw ExecutionException("RPC dependency method cannot be reread from its APK")
        val inspected = inspect(s, producer, method, service, rpc)
        val role = rule.parameters.string("role")!!
        return selectRelatedTypes(inspected.bindings, inspected.unknown, role,
            { type -> (s.classes[type]?.flags ?: 0) and 0x200 != 0 }, s::isSubtype).map { selected ->
            val binding = selected.binding
            if (selected.type !in s.classes) throw ExecutionException("RPC dependency construction references an unavailable role type: ${selected.type}")
            val related = binding.related + method.id.owner + listOf(binding.descriptorType, binding.builderType,
                binding.requestDeclarationType, binding.responseDeclarationType,
                binding.requestImplementationType, binding.responseImplementationType)
            MessagesRecipes.fact(s, selected.type, selected.status, "rpc-related-type", selected.detail,
                captures = mapOf("service" to service, "rpc" to rpc, "role" to role,
                    "descriptorType" to binding.descriptorType, "builderType" to binding.builderType,
                    "requestDeclarationType" to binding.requestDeclarationType, "responseDeclarationType" to binding.responseDeclarationType,
                    "requestImplementationType" to binding.requestImplementationType, "responseImplementationType" to binding.responseImplementationType),
                related = related.toList(), source = method.id, offset = binding.offset)
        }
    }

    /** Method uniqueness does not establish completeness of its internal construction paths. */
    internal fun selectRelatedTypes(bindings: List<Binding>, incomplete: Boolean, role: String,
        isInterface: (String) -> Boolean, isSubtype: (String, String) -> Boolean): List<RelatedType> {
        if (bindings.isEmpty()) throw ExecutionException("RPC dependency proof cannot reproduce any complete descriptor construction")
        val invalidMarshaller = role == "marshaller" && bindings.any { binding ->
            binding.requestDeclarationType != binding.responseDeclarationType || !isInterface(binding.requestDeclarationType) ||
                !isSubtype(binding.requestImplementationType, binding.requestDeclarationType) ||
                !isSubtype(binding.responseImplementationType, binding.responseDeclarationType)
        }
        // Never append UNKNOWN next to PASS for one class: normal entity deduplication prefers PASS.
        val unknown = incomplete || invalidMarshaller
        val detail = when {
            incomplete -> "An RPC construction path is unresolved; all known related types remain unknown"
            invalidMarshaller -> "RPC marshaller fields do not establish one common declared interface with compatible implementations"
            else -> "Related type is bound to the verified RPC descriptor construction"
        }
        return bindings.flatMap { binding ->
            val targets = when (role) {
                "descriptor" -> listOf(binding.descriptorType)
                "builder" -> listOf(binding.builderType)
                "marshaller" -> listOf(binding.requestDeclarationType, binding.responseDeclarationType).distinct()
                else -> error("Unvalidated RPC related type role: $role")
            }
            targets.map { RelatedType(it, if (unknown) MatchStatus.UNKNOWN else MatchStatus.PASS, binding, detail) }
        }
    }

    private fun inspect(s: DexFactSession, rule: RuleRevision, method: Method, service: String, rpc: String): Inspection {
        val trace = s.trace(method)
        if (!trace.complete) return Inspection(emptyList(), true, trace.reason ?: "Unreadable descriptor construction")
        val nameCalls = trace.calls.filter { call -> call.args == listOf(Value.Text(service), Value.Text(rpc)) && call.method.result == "Ljava/lang/String;" }
        if (nameCalls.isEmpty()) return Inspection(emptyList(), false, "No bound service/RPC invocation")
        val inspected = nameCalls.map { inspectCall(s, rule, method, it) }
        return Inspection(inspected.flatMap { it.bindings }.distinct(), inspected.any { it.unknown },
            "Descriptor role, constructor transfer or marshaller default instance is outside supported local shapes")
    }

    /** Shared construction reader for known RPC rules and dependency-driven full-APK discovery. */
    internal fun inspectCall(s: DexFactSession, rule: RuleRevision, method: Method, name: CallEvent,
                             descriptorType: String? = null): Inspection {
        val trace = s.trace(method)
        if (!trace.complete) return Inspection(emptyList(), true, trace.reason ?: "Unreadable descriptor construction")
        val bindings = mutableListOf<Binding>(); var unknown = false
        run {

            val value = Value.Invocation(name.offset, name.method, name.receiver, name.args)
            val nameWrites = trace.writes.filter { it.value == value && it.receiver != null }
            if (nameWrites.isEmpty()) unknown = true
            for (nameWrite in nameWrites) {
                val builder = nameWrite.receiver!!
                val builds = trace.calls.filter { it.offset > nameWrite.offset && it.receiver == builder && it.method.args.isEmpty() &&
                    it.method.result in s.classes && (descriptorType == null || it.method.result == descriptorType) }
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
                        val related = linkedSetOf(descriptor, build.method.owner, constructor.method.owner, name.method.owner, req.messageType, res.messageType)
                        related += req.related; related += res.related
                        bindings += Binding(method.id, req.messageType, res.messageType, descriptor, build.method.owner,
                            labels.getValue("request").type, labels.getValue("response").type,
                            req.implementationType, res.implementationType, related.filter { it in s.classes }.toSet(), name.offset)
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

    private fun defaultType(s: DexFactSession, value: Value?, constructions: Map<Value, CallEvent>, depth: Int): Marshaller? {
        when (value) {
            is Value.Allocation -> {
                val constructor = constructions[value] ?: return null
                val defaults = constructor.args.mapNotNull { defaultInstance(s, it) }.distinct()
                return defaults.singleOrNull()?.let { Marshaller(it, value.type, setOf(value.type, constructor.method.owner)) }
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
                return defaults.singleOrNull()?.let { Marshaller(it, allocation.type, setOf(value.method.owner, allocation.type)) }
            }
            else -> return null
        }
    }

    private fun defaultInstance(s: DexFactSession, value: Value): String? {
        val read = value as? Value.FieldRead ?: return null
        if (read.receiver != null || read.field.owner != read.field.type || read.field.owner !in s.classes) return null
        return s.fields(read.field.owner).singleOrNull { it.key == read.field.key && it.flags and 8 != 0 }?.type
    }

    private fun staticDefaultTypes(s: DexFactSession, method: Method): Set<String> = MethodCodeFacts.staticReads(method)
        .filter { it.owner == it.type && it.type in s.classes }.map { it.type }.toCollection(linkedSetOf())
}
