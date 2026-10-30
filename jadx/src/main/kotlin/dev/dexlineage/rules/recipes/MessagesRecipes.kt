package dev.dexlineage.rules.recipes

import dev.dexlineage.model.*
import dev.dexlineage.rules.*
import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*

/** Application recipes express observed conventions using current-APK facts and configured literals. */
internal object MessagesRecipes {
    fun execute(s: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): List<MatchFact> = when (rule.strategyId) {
        "builtin.method-signature" -> methodSignature(s, rule, dependencies.getValue("owner"))
        "messages.logger-fields" -> loggerFields(s, rule, dependencies.getValue("factory"))
        "messages.handler-name-method" -> handlerNameMethod(s, rule, dependencies.getValue("lifecycle"))
        "messages.named-handler" -> namedHandlers(s, rule, dependencies.getValue("nameMethod"))
        "messages.rpc-descriptor", "messages.rpc-message" -> RpcRecipe.execute(s, rule, dependencies)
        else -> error("Unregistered execution strategy ${rule.strategyId}")
    }

    private fun methodSignature(s: DexFactSession, rule: RuleRevision, anchor: SupportAnchor): List<MatchFact> {
        val p = rule.parameters; val owner = anchor.binding.owner
        return s.methods(owner.descriptor).filter { method ->
            method.id.args == p.array("parameterTypes") && (p.string("returnType") == null || method.id.result == p.string("returnType")) &&
                (p.get("returnSameAsOwner")?.asBoolean != true || method.id.result == owner.descriptor) &&
                p.array("requiredFlags").orEmpty().all { method.flags and StrategyRegistry.flags.getValue(it) != 0 }
        }.map { method -> fact(s, method.id.owner, MatchStatus.PASS, "method-signature", "Exact original method signature and access flags", method = method.id) }
    }

    private fun loggerFields(s: DexFactSession, rule: RuleRevision, anchor: SupportAnchor): List<MatchFact> {
        val factory = s.method(anchor.binding.method!!) ?: error("Factory method absent from current APK")
        val p = rule.parameters; val tag = p.string("tag"); val component = p.string("component"); val capture = p.number("captureIndex", 1)
        val scope = listOfNotNull(tag, component).firstOrNull()?.let { s.scan.uses[it].orEmpty().map { use -> use.classDescriptor }.toSet() }
            ?: s.callOwners[factory.id.key].orEmpty()
        val required = p.array("requiredFlags") ?: listOf("STATIC", "FINAL")
        val result = mutableListOf<MatchFact>()
        for (owner in scope.sorted()) {
            val fields = s.fields(owner).filter { it.type == factory.id.result && required.all { flag -> it.flags and StrategyRegistry.flags.getValue(flag) != 0 } }
            if (fields.isEmpty()) continue
            val initializers = s.methods(owner).filter { it.id.name in setOf("<clinit>", "<init>") }
            for (field in fields) {
                var writes = 0
                for (method in initializers) {
                    val trace = s.trace(method)
                    if (!trace.complete) {
                        result += fact(s, owner, MatchStatus.UNKNOWN, "initializer", trace.reason!!, related = listOf(factory.id.owner), source = method.id)
                        continue
                    }
                    trace.writes.filter { it.field.key == field.key }.forEach { write ->
                        writes++
                        val call = write.value as? Value.Invocation
                        if (call == null) {
                            if (write.value == Value.Unknown) result += fact(s, owner, MatchStatus.UNKNOWN, "initializer", "Initializer result is unresolved", related = listOf(factory.id.owner), source = method.id, offset = write.offset)
                            return@forEach
                        }
                        if (call.method != factory.id || call.receiver != null) return@forEach
                        val values = call.args.map { (it as? Value.Text)?.value }
                        val mismatch = (tag != null && values.getOrNull(0) != null && values[0] != tag) ||
                            (component != null && values.getOrNull(capture) != null && values[capture] != component)
                        if (mismatch) return@forEach
                        val status = if (values.getOrNull(capture) == null || tag != null && values.getOrNull(0) == null) MatchStatus.UNKNOWN else MatchStatus.PASS
                        val captured = values.getOrNull(capture)?.let { mapOf("component" to it) }.orEmpty()
                        val binding = FieldBinding(s.ref(owner), field.name, field.type, field.flags, method.id.shortId,
                            CallFact(factory.id.owner, factory.id.name, factory.id.args, factory.id.result, "STATIC", values, call.site), owner)
                        result += fact(s, owner, status, "logger-initializer", "Bound field assignment invokes the resolved factory", captures = captured,
                            related = listOf(factory.id.owner), source = method.id, offset = write.offset).copy(field = binding)
                    }
                }
                if (writes == 0 && listOfNotNull(tag, component).isNotEmpty()) result += fact(s, owner, MatchStatus.UNKNOWN, "initializer", "Matching logger field has no reliable assignment", related = listOf(factory.id.owner))
            }
        }
        return result
    }

    private fun handlerNameMethod(s: DexFactSession, rule: RuleRevision, anchor: SupportAnchor): List<MatchFact> {
        val literal = rule.parameters.string("logLiteral")!!; val index = rule.parameters.number("argumentIndex", 0)
        val owner = anchor.binding.owner.descriptor
        val methodsWithLiteral = s.scan.uses[literal].orEmpty().filter { it.classDescriptor == owner }.map { it.methodDescriptor }.toSet()
        val result = mutableListOf<MatchFact>()
        s.methods(owner).filter { it.id.shortId in methodsWithLiteral }.forEach { method ->
            val trace = s.trace(method)
            if (!trace.complete) {
                // No target role is guessed from signature alone. All same-shape invocation possibilities remain unknown.
                val possibilities = methodInvocations(method).filter { it.args.isEmpty() && it.result == "Ljava/lang/String;" && it.owner in s.classes }
                possibilities.forEach { result += fact(s, it.owner, MatchStatus.UNKNOWN, "log-argument-role", trace.reason!!, method = it, related = listOf(owner), source = method.id) }
                return@forEach
            }
            trace.calls.filter { call -> call.args.any { it == Value.Text(literal) } }.forEach { call ->
                val arrays = call.args.filterIsInstance<Value.Array>()
                val values = arrays.map { call.arrays[it]?.get(index) ?: Value.Unknown }
                val invocations = values.filterIsInstance<Value.Invocation>().filter { it.method.args.isEmpty() && it.method.result == "Ljava/lang/String;" && it.method.owner in s.classes }
                invocations.forEach { value -> result += fact(s, value.method.owner, MatchStatus.PASS, "log-argument-role", "Configured log array slot $index is produced by this no-argument String method",
                    method = value.method, related = listOf(owner, call.method.owner).filter { it in s.classes }, source = method.id, offset = call.offset) }
                if (invocations.isEmpty() && (arrays.isEmpty() || values.any { it == Value.Unknown })) {
                    methodInvocations(method).filter { it.args.isEmpty() && it.result == "Ljava/lang/String;" && it.owner in s.classes }.forEach {
                        result += fact(s, it.owner, MatchStatus.UNKNOWN, "log-argument-role", "Log argument producer is unresolved", method = it, related = listOf(owner), source = method.id, offset = call.offset)
                    }
                }
            }
        }
        return result
    }

    private fun namedHandlers(s: DexFactSession, rule: RuleRevision, anchor: SupportAnchor): List<MatchFact> {
        val role = anchor.binding.method!!; val component = rule.parameters.string("component")
        return s.implementations(role.owner.descriptor).mapNotNull { cls ->
            val method = s.inheritedMethod(cls.ref.descriptor, role.name, role.descriptor)
            if (method == null) return@mapNotNull fact(s, cls.ref.descriptor, MatchStatus.UNKNOWN, "constant-method-return", "Concrete implementation has no readable implementation method", related = listOf(role.owner.descriptor))
            val trace = s.trace(method); val values = trace.returns.map { it.value }.distinct(); val name = values.singleOrNull() as? Value.Text
            if (trace.complete && name != null && component != null && name.value != component) return@mapNotNull null
            val status = if (trace.complete && name != null) MatchStatus.PASS else MatchStatus.UNKNOWN
            fact(s, cls.ref.descriptor, status, "constant-method-return", if (status == MatchStatus.PASS) "All normal returns of the resolved implementation are this string" else trace.reason ?: "Method return is not a single known string constant",
                captures = name?.let { mapOf("component" to it.value) }.orEmpty(), related = listOf(role.owner.descriptor, method.id.owner), source = method.id,
                offset = trace.returns.firstOrNull()?.offset)
        }
    }

    internal fun methodInvocations(method: Method): Set<MethodId> {
        val result = linkedSetOf<MethodId>()
        method.code?.visitInstructions { i ->
            if (i.opcode.name.startsWith("INVOKE_")) { i.decode(); if (i.indexType == jadx.api.plugins.input.insns.InsnIndexType.METHOD_REF) {
                val r = i.indexAsMethod.also { it.load() }; result += MethodId(r.parentClassType, r.name, r.argTypes.toList(), r.returnType)
            } }
        }
        return result
    }
    internal fun fact(s: DexFactSession, owner: String, status: MatchStatus, kind: String, detail: String,
        captures: Map<String, String> = emptyMap(), method: MethodId? = null, related: List<String> = emptyList(),
        source: MethodId? = null, offset: Int? = null): MatchFact = MatchFact(s.ref(owner), status, listOf(FactorResult(kind, status, detail)), captures,
        method = method?.let(s::methodRef), relatedRefs = related.filter { it in s.classes }.distinct().sorted().map(s::ref),
        trace = listOf(FactTrace(s.ref(source?.owner ?: owner), source?.shortId, offset, kind, detail)))
}
