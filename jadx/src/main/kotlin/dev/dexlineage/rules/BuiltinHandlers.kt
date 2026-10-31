package dev.dexlineage.rules

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.facts.DexFactSession

internal object LocatorHandler : MatchingHandler {
    override val id = "builtin.locators"
    override val resultKind = EntityKind.CLASS
    override val dependencyKinds = emptyMap<String, EntityKind>()
    override fun validate(rule: RuleRevision) {
        requireInput(rule.parameters.size() == 0, "Builtin locators have no parameters")
        rule.locators.forEach(RuleEngine::validate)
    }
    override fun scanNeeds(rule: RuleRevision) = ScanNeeds(rule.locators.map { it.anchor }.toSet())
    override fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult =
        error("Locator execution uses the existing batched locator adapter")
}

internal object MethodSignatureHandler : MatchingHandler {
    override val id = "builtin.method-signature"
    override val resultKind = EntityKind.METHOD
    override val dependencyKinds = mapOf("owner" to EntityKind.CLASS)
    override fun validate(rule: RuleRevision) {
        HandlerInputs.only(rule, setOf("parameterTypes", "returnType", "returnSameAsOwner", "requiredFlags"))
        requireInput(rule.parameters.has("parameterTypes"), "Method signature needs parameterTypes")
        HandlerInputs.stringArray(rule, "parameterTypes")
        rule.parameters.array("parameterTypes").orEmpty().forEach { requireInput(HandlerInputs.descriptor(it, false), "Invalid parameter type: $it") }
        HandlerInputs.strings(rule, setOf("returnType"))
        rule.parameters.string("returnType")?.let { requireInput(HandlerInputs.descriptor(it, true), "Invalid return type: $it") }
        rule.parameters.get("returnSameAsOwner")?.let { requireInput(it.isJsonPrimitive && it.asJsonPrimitive.isBoolean, "Expected boolean: returnSameAsOwner") }
        HandlerInputs.accessFlags(rule)
    }
    override fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult {
        val p = rule.parameters; val owner = dependencies.getValue("owner").binding.owner
        return StrategyResult(session.methods(owner.descriptor).filter { method ->
            method.id.args == p.array("parameterTypes") && (p.string("returnType") == null || method.id.result == p.string("returnType")) &&
                (p.get("returnSameAsOwner")?.asBoolean != true || method.id.result == owner.descriptor) &&
                p.array("requiredFlags").orEmpty().all { flag -> method.flags and HandlerInputs.flags.getValue(flag) != 0 }
        }.map { method ->
            val detail = "Exact original method signature and access flags"
            MatchFact(owner, MatchStatus.PASS, listOf(FactorResult("method-signature", MatchStatus.PASS, detail)), emptyMap(),
                method = session.methodRef(method.id), trace = listOf(FactTrace(owner, null, null, "method-signature", detail)))
        })
    }
}
