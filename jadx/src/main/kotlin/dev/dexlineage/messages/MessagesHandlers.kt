package dev.dexlineage.messages

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import dev.dexlineage.rules.*
import dev.dexlineage.rules.facts.DexFactSession

/** All Messages conventions are registered here, including the persisted grpc-java.* identifiers. */
internal object MessagesHandlers {
    private val rpcLabels = setOf("requestLabel", "responseLabel", "nameLabel")

    val all: List<MatchingHandler> = listOf(
        handler("messages.logger-fields", EntityKind.CLASS, mapOf("factory" to EntityKind.METHOD),
            setOf("tag", "component")) { rule ->
            HandlerInputs.only(rule, setOf("tag", "component", "captureIndex", "requiredFlags"))
            HandlerInputs.strings(rule, setOf("tag", "component")); HandlerInputs.index(rule, "captureIndex"); HandlerInputs.accessFlags(rule)
        },
        handler("messages.handler-name-method", EntityKind.METHOD, mapOf("lifecycle" to EntityKind.CLASS),
            setOf("logLiteral")) { rule ->
            HandlerInputs.only(rule, setOf("logLiteral", "argumentIndex"))
            HandlerInputs.requiredString(rule, "logLiteral"); HandlerInputs.index(rule, "argumentIndex")
        },
        handler("messages.named-handler", EntityKind.CLASS, mapOf("nameMethod" to EntityKind.METHOD),
            setOf("component")) { rule ->
            HandlerInputs.only(rule, setOf("component")); HandlerInputs.strings(rule, setOf("component"))
        },
        handler("messages.rpc-descriptor", EntityKind.METHOD, emptyMap(), setOf("service", "rpc")) { rule ->
            rpcParameters(rule, false)
        },
        handler("messages.rpc-message", EntityKind.CLASS, mapOf("descriptor" to EntityKind.METHOD), setOf("service", "rpc")) { rule ->
            rpcParameters(rule, true)
        },
        handler("messages.rpc-related-type", EntityKind.CLASS, mapOf("descriptor" to EntityKind.METHOD),
            producer = "descriptor" to "messages.rpc-descriptor") { rule ->
            HandlerInputs.only(rule, setOf("role")); HandlerInputs.requiredString(rule, "role")
            requireInput(rule.parameters.string("role") in setOf("descriptor", "builder", "marshaller"), "RPC related type role must be descriptor, builder or marshaller")
        },
        handler("grpc-java.full-method-name", EntityKind.METHOD, mapOf("descriptor" to EntityKind.CLASS), grpc = true) { rule ->
            HandlerInputs.only(rule, emptySet())
        },
        handler("grpc-java.rpc-discovery", EntityKind.CLASS, mapOf("nameFactory" to EntityKind.METHOD),
            producer = "nameFactory" to "grpc-java.full-method-name", grpc = true, evidence = EvidenceMode.ON_INSPECT) { rule ->
            HandlerInputs.only(rule, rpcLabels); HandlerInputs.strings(rule, rpcLabels)
        },
        handler("grpc-java.rpc-message", EntityKind.CLASS, mapOf("nameFactory" to EntityKind.METHOD),
            producer = "nameFactory" to "grpc-java.full-method-name", grpc = true, evidence = EvidenceMode.ON_INSPECT) { rule ->
            HandlerInputs.only(rule, rpcLabels + "selectors"); HandlerInputs.strings(rule, rpcLabels)
            val selectors = rule.parameters.get("selectors")
            requireInput(selectors != null && selectors.isJsonArray && selectors.asJsonArray.size() > 0, "RPC selectors must be a nonempty array")
            selectors.asJsonArray.forEach { selector ->
                requireInput(selector.isJsonObject && selector.asJsonObject.keySet() == setOf("service", "rpc", "role"), "RPC selector requires only service, rpc and role")
                selector.asJsonObject.entrySet().forEach { (_, value) ->
                    requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isString && value.asString.isNotBlank(), "RPC selector values must be nonempty strings")
                }
                requireInput(selector.asJsonObject.get("role").asString in setOf("request", "response"), "Invalid RPC selector role")
            }
            val parsed = GrpcJavaRecipe.selectors(rule)
            requireInput(parsed.distinct().size == parsed.size, "Duplicate RPC selectors")
        },
    )

    private fun rpcParameters(rule: RuleRevision, withRole: Boolean) {
        HandlerInputs.only(rule, rpcLabels + setOf("service", "rpc") + if (withRole) setOf("role") else emptySet())
        HandlerInputs.strings(rule, rpcLabels)
        HandlerInputs.requiredString(rule, "service"); HandlerInputs.requiredString(rule, "rpc")
        if (withRole) {
            HandlerInputs.requiredString(rule, "role")
            requireInput(rule.parameters.string("role") in setOf("request", "response"), "RPC message role must be request or response")
        }
    }

    private fun handler(id: String, kind: EntityKind, roles: Map<String, EntityKind>, literalKeys: Set<String> = emptySet(),
        producer: Pair<String, String>? = null, grpc: Boolean = false, evidence: EvidenceMode = EvidenceMode.EAGER,
        validator: (RuleRevision) -> Unit): MatchingHandler = object : MatchingHandler {
        override val id = id
        override val resultKind = kind
        override val dependencyKinds = roles
        override val evidenceMode = evidence
        override fun validate(rule: RuleRevision) = validator(rule)
        override fun validateProducers(rule: RuleRevision, producers: Map<String, RuleRevision>) {
            producer?.let { (role, expected) ->
                val actual = producers.getValue(rule.requires.getValue(role))
                requireInput(actual.strategyId == expected, "${rule.strategyId} requires $role produced by $expected")
                StrategyRegistry.validate(actual)
            }
        }
        override fun scanNeeds(rule: RuleRevision) = ScanNeeds(literalKeys.mapNotNull { rule.parameters.string(it) }.toSet())
        override fun execute(session: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult =
            if (grpc) GrpcJavaRecipe.execute(session, rule, dependencies)
            else StrategyResult(MessagesRecipes.execute(session, rule, dependencies))
    }
}
