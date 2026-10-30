package dev.dexlineage.messages

import dev.dexlineage.io.ExecutionException
import dev.dexlineage.io.JsonFiles
import dev.dexlineage.model.*
import dev.dexlineage.rules.StrategyResult
import dev.dexlineage.rules.TypedArtifact
import dev.dexlineage.rules.facts.*
import dev.dexlineage.rules.facts.DexFactSession.*

/** Finite gRPC Java construction discovery through a mechanically resolved name factory. */
internal object GrpcJavaRecipe {
    data class Selector(val service: String, val rpc: String, val role: String)
    private data class Site(val observation: RpcCallObservation, val bindings: List<RpcRecipe.Binding>,
                            val unresolved: RpcUnresolvedPath?)
    private data class Catalogue(val sites: List<Site>)
    private const val STRING = "Ljava/lang/String;"
    private const val BUILDER = "Ljava/lang/StringBuilder;"

    fun execute(s: DexFactSession, rule: RuleRevision, dependencies: Map<String, SupportAnchor>): StrategyResult {
        if (rule.strategyId == "grpc-java.full-method-name") {
            val owner = dependencies.getValue("descriptor").binding.owner
            val facts = s.methods(owner.descriptor).filter {
                it.flags and 8 != 0 && it.id.args == listOf(STRING, STRING) && it.id.result == STRING
            }.map { method ->
                val trace = s.trace(method)
                val straightLine = MethodCodeFacts.controlShape(method).straightLine
                val status = fullMethodNameStatus(trace, straightLine)
                MessagesRecipes.fact(s, owner.descriptor, status, "full-method-name-body",
                    when (status) {
                        MatchStatus.PASS -> "Static two-String method returns argument zero, slash and argument one through a straight-line StringBuilder"
                        MatchStatus.FAIL -> "Readable return does not implement the supported full-method-name concatenation"
                        MatchStatus.UNKNOWN -> trace.reason ?: "Full-method-name body is outside the supported straight-line StringBuilder shape"
                    }, method = method.id, source = method.id)
            }
            return StrategyResult(facts)
        }
        val factory = dependencies.getValue("nameFactory").binding.method!!
        val labels = listOf("nameLabel", "requestLabel", "responseLabel").associateWith { rule.parameters.get(it)?.asString }
        val cacheKey = "grpc-java-catalogue\n${factory.owner.descriptor}\n${factory.name}${factory.descriptor}\n${JsonFiles.encode(labels)}"
        val catalogue = s.cachedRecipe(cacheKey) { catalogue(s, rule, factory) }
        val selectors = if (rule.strategyId == "grpc-java.rpc-message") selectors(rule) else null
        val facts = mutableListOf<MatchFact>()
        val unresolved = mutableListOf<RpcUnresolvedPath>()
        for (site in catalogue.sites) {
            val observation = site.observation
            val service = observation.service; val rpc = observation.rpc
            site.unresolved?.let { path ->
                if (selectors == null || selectors.any { mayMatch(path, it) }) unresolved += path
            }
            if (service == null || rpc == null) continue
            for (binding in site.bindings) {
                for ((role, type) in listOf("request" to binding.request, "response" to binding.response)) {
                    if (selectors != null && Selector(service, rpc, role) !in selectors) continue
                    facts += MessagesRecipes.fact(s, type, MatchStatus.PASS, "grpc-rpc-role",
                        "Resolved full-method-name call, builder transfer and marshaller default instance form one RPC $role relation",
                        captures = mapOf("service" to service, "rpc" to rpc, "role" to role),
                        related = (binding.related + binding.method.owner + factory.owner.descriptor).toList(),
                        source = binding.method, offset = binding.offset)
                }
            }
        }
        val artifact = MessagesRpcCatalogue(apkSha256 = s.artifact.sha256, nameFactory = factory,
            calls = catalogue.sites.map { it.observation }, unresolvedPaths = catalogue.sites.mapNotNull { it.unresolved }.distinct())
        return StrategyResult(facts, unresolved.distinct().map { it.uncertainty() }, listOf(TypedArtifact(MessagesRpcArtifacts.KIND, artifact)))
    }

    fun selectors(rule: RuleRevision): List<Selector> = rule.parameters.getAsJsonArray("selectors").map {
        val value = it.asJsonObject
        Selector(value.get("service").asString, value.get("rpc").asString, value.get("role").asString)
    }

    internal fun mayMatch(path: RpcUnresolvedPath, selector: Selector): Boolean =
        (path.service == null || path.service == selector.service) &&
            (path.rpc == null || path.rpc == selector.rpc) && (path.role == null || path.role == selector.role)

    private fun catalogue(s: DexFactSession, rule: RuleRevision, factory: MethodRef): Catalogue {
        val factoryId = s.method(factory)?.id ?: throw ExecutionException("Name-factory dependency method absent from APK")
        val sites = s.wantedCallSites.filter { it.target == factoryId }
            .distinct().sortedWith(compareBy({ it.source.key }, { it.offset })).map { site ->
                val method = s.method(site.source) ?: throw ExecutionException("Name-factory caller absent from APK")
                val source = s.methodRef(method.id)
                val trace = s.trace(method)
                val call = trace.calls.singleOrNull { it.offset == site.offset && it.method == factoryId }
                val service = (call?.args?.getOrNull(0) as? Value.Text)?.value?.takeIf { it.isNotBlank() }
                val rpc = (call?.args?.getOrNull(1) as? Value.Text)?.value?.takeIf { it.isNotBlank() }
                if (!trace.complete) {
                    val reason = trace.reason ?: "Unreadable name-factory caller"
                    Site(RpcCallObservation(source, site.offset, service, rpc, "UNRESOLVED_CONSTRUCTION", diagnostics = listOf(reason)),
                        emptyList(), RpcUnresolvedPath(source, site.offset, reason, service, rpc))
                } else if (call == null || !potentialConstruction(s, trace, call, factory.owner.descriptor)) {
                    val reason = if (call == null) "Raw invocation is unreachable in the supported control-flow trace"
                        else "Name-factory result does not feed a possible descriptor construction in this method"
                    Site(RpcCallObservation(source, site.offset, service, rpc, "NON_CONSTRUCTION", diagnostics = listOf(reason)), emptyList(), null)
                } else {
                    val inspected = RpcRecipe.inspectCall(s, rule, method, call, factory.owner.descriptor)
                    val incomplete = inspected.unknown || service == null || rpc == null || inspected.bindings.isEmpty()
                    val reason = if (service == null || rpc == null) "Descriptor construction has an unresolved service or RPC argument" else inspected.detail
                    Site(RpcCallObservation(source, site.offset, service, rpc,
                        if (incomplete) "UNRESOLVED_CONSTRUCTION" else "RESOLVED",
                        inspected.bindings.map { s.ref(it.request) }.distinct().sortedBy { it.descriptor },
                        inspected.bindings.map { s.ref(it.response) }.distinct().sortedBy { it.descriptor },
                        if (incomplete) listOf(reason) else emptyList()), inspected.bindings,
                        if (incomplete) RpcUnresolvedPath(source, site.offset, reason, service, rpc) else null)
                }
            }
        return Catalogue(sites)
    }

    /** A dynamic full-name call used only by a map/config parser is not a possible Proto binding. */
    private fun potentialConstruction(s: DexFactSession, trace: RawTrace, call: CallEvent, descriptor: String): Boolean {
        return potentialConstruction(trace, call, descriptor, { it in s.classes }, { type ->
            type in s.classes && s.methods(type).any { it.id.args.isEmpty() && it.id.result == descriptor && it.flags and 8 == 0 }
        }, { use -> GrpcDiagnosticGuard.accepts(s, use) && use.args.getOrNull(2)?.let { isNameResult(it, call) } == true })
    }

    internal fun potentialConstruction(trace: RawTrace, call: CallEvent, descriptor: String,
        isApplicationType: (String) -> Boolean, isBuilder: (String) -> Boolean,
        isDiagnosticUse: (CallEvent) -> Boolean = { false }): Boolean {
        fun uncertainOrName(value: Value) = value == Value.Unknown || isNameResult(value, call)
        // A field escape may be consumed by a later method; absence of a local build is not exclusion.
        if (trace.writes.any { it.offset > call.offset && isNameResult(it.value, call) }) return true
        if (trace.writes.any { it.offset > call.offset && it.receiver != null && isBuilder(it.field.owner) && uncertainOrName(it.value) }) return true
        // An unsupported application helper or returned name can hide a construction in a caller/callee.
        // Do not claim that lack of a local supported build proves it is merely a configuration use.
        if (trace.returns.any { isNameResult(it.value, call) }) return true
        return trace.calls.any { use ->
            if (use.offset <= call.offset) false
            else if (use.method.result == descriptor || use.method.owner == descriptor && use.method.name == "<init>" || isBuilder(use.method.owner))
                use.args.any(::uncertainOrName)
            else isApplicationType(use.method.owner) && use.args.any { isNameResult(it, call) } && !isDiagnosticUse(use)
        }
    }

    internal fun isNameResult(value: Value, call: CallEvent): Boolean = when (value) {
        is Value.Invocation -> value.site == call.offset && value.method == call.method
        is Value.CallResult -> value.site == call.offset && value.method == call.method
        else -> false
    }

    /** Deliberately finite: no assumptions about arbitrary StringBuilder mutators or conditional append order. */
    internal fun fullMethodNameStatus(trace: RawTrace, straightLine: Boolean): MatchStatus {
        if (!trace.complete || !straightLine || trace.returns.size != 1) return MatchStatus.UNKNOWN
        val returned = trace.returns.single().value
        if (returned is Value.Text || returned is Value.Parameter) return MatchStatus.FAIL
        val render = returned as? Value.Invocation ?: return MatchStatus.UNKNOWN
        if (render.method.owner != BUILDER || render.method.name != "toString" || render.method.args.isNotEmpty() || render.method.result != STRING) return MatchStatus.UNKNOWN
        fun root(value: Value?): Value? = if (value is Value.Invocation && value.method.owner == BUILDER && value.method.name == "append") root(value.receiver) else value
        val instance = root(render.receiver) as? Value.Allocation ?: return MatchStatus.UNKNOWN
        if (instance.type != BUILDER) return MatchStatus.UNKNOWN
        if (trace.calls.any { call ->
            val builderCall = root(call.receiver) == instance && call.method.owner == BUILDER && call.method.name in setOf("<init>", "append", "toString")
            val nullCheck = call.method.owner in setOf("Ljava/lang/Object;", STRING) && call.method.name == "getClass" &&
                call.method.args.isEmpty() && call.receiver is Value.Parameter && call.args.isEmpty()
            !builderCall && !nullCheck
        } || trace.writes.isNotEmpty()) return MatchStatus.UNKNOWN
        val calls = trace.calls.filter { root(it.receiver) == instance && it.offset < render.site }
        val constructor = calls.singleOrNull { it.method.name == "<init>" } ?: return MatchStatus.UNKNOWN
        if (calls.any { it.method.owner != BUILDER || it.method.name !in setOf("<init>", "append") }) return MatchStatus.UNKNOWN
        val tokens = mutableListOf<Value>()
        if (constructor.method.args == listOf(STRING)) tokens += constructor.args.single()
        else if (constructor.method.args.isNotEmpty()) return MatchStatus.UNKNOWN
        for (append in calls.filter { it.method.name == "append" }) {
            if (append.method.args != listOf(STRING) || append.args.size != 1) return MatchStatus.UNKNOWN
            tokens += append.args.single()
        }
        val expected = listOf(Value.Parameter(0, STRING), Value.Text("/"), Value.Parameter(1, STRING))
        if (tokens == expected) return MatchStatus.PASS
        return if (tokens.all { it is Value.Parameter || it is Value.Text }) MatchStatus.FAIL else MatchStatus.UNKNOWN
    }
}
