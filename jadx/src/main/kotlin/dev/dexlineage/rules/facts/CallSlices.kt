package dev.dexlineage.rules.facts

import dev.dexlineage.io.ExecutionException
import dev.dexlineage.rules.facts.DexFactSession.*
import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode
import jadx.api.plugins.input.insns.custom.ISwitchPayload

internal data class SliceUncertainty(val offset: Int?, val reason: String, val relevantCallOffsets: Set<Int>? = null)
internal data class CallSliceResult(val paths: List<RawTrace>, val uncertainties: List<SliceUncertainty>)

/** Bounded path-sensitive call/return facts. No domain format or selector semantics live here.
 * Each path owns its registers, allocations and pre-call array snapshots; branches are never merged.
 * Incomplete paths retain their prefix for diagnostics, but cannot establish a returned result.
 */
internal object CallSlices {
    private const val MAX_PATHS = 128
    private const val MAX_STEPS = 20000
    private const val MAX_ARRAY = 4096
    private data class Insn(val op: Opcode, val offset: Int, val regs: List<Int>, val resultReg: Int,
        val literal: Long, val target: Int, val text: String?, val type: String?, val method: MethodId?,
        val field: Field?, val switchKeys: List<Int>?, val switchTargets: List<Int>?)
    private data class State(val index: Int, val regs: Map<Int, Value>, val result: Value = Value.Unknown,
        val fields: Map<Value, Map<Field, Value>> = emptyMap(),
        val arrays: Map<Value.Array, Map<Int, Value>> = emptyMap(),
        val constructions: Map<Value, CallEvent> = emptyMap(),
        val calls: List<CallEvent> = emptyList(), val writes: List<WriteEvent> = emptyList(),
        val escapedArrays: Set<Value.Array> = emptySet(), val arrayEffects: List<ArrayEffect> = emptyList(),
        val visited: Set<Int> = emptySet())

    fun read(method: Method): CallSliceResult {
        val reader = method.code ?: return CallSliceResult(emptyList(), listOf(SliceUncertainty(null, "Method has no readable body")))
        val insns = mutableListOf<Insn>()
        reader.visitInstructions { i ->
            i.decode()
            val m = if (i.indexType == InsnIndexType.METHOD_REF) i.indexAsMethod.also { it.load() } else null
            val f = if (i.indexType == InsnIndexType.FIELD_REF) i.indexAsField else null
            val payload = i.payload as? ISwitchPayload
            insns += Insn(i.opcode, i.offset, (0 until i.regsCount).map(i::getReg), i.resultReg,
                i.literal, i.target, if (i.opcode == Opcode.CONST_STRING) i.indexAsString else null,
                if (i.indexType == InsnIndexType.TYPE_REF) i.indexAsType else null,
                m?.let { MethodId(it.parentClassType, it.name, it.argTypes.toList(), it.returnType) },
                f?.let { Field(it.parentClassType, it.name, it.type) }, payload?.keys?.toList(), payload?.targets?.toList())
        }
        if (insns.isEmpty()) return CallSliceResult(emptyList(), listOf(SliceUncertainty(null, "Empty method body")))
        val indices = insns.mapIndexed { index, i -> i.offset to index }.toMap()
        fun target(offset: Int): Int = indices[offset] ?: throw ExecutionException("Invalid branch target $offset in ${method.id.key}")
        fun switchBranches(i: Insn): List<Pair<Int, Int>> {
            val payload = insns[target(i.target)]
            val keys = payload.switchKeys ?: throw ExecutionException("Missing switch payload in ${method.id.key} at ${i.offset}")
            val deltas = payload.switchTargets ?: throw ExecutionException("Missing switch targets in ${method.id.key}")
            if (keys.size != deltas.size) throw ExecutionException("Invalid switch payload size in ${method.id.key}")
            // DEX payload targets are relative to the switch instruction, not the payload.
            return keys.zip(deltas).map { (key, delta) -> key to target(i.offset + delta) }
        }
        fun successors(index: Int): List<Int> {
            val i = insns[index]
            val next = (index + 1).takeIf { it < insns.size }
            return when {
                i.op in setOf(Opcode.RETURN, Opcode.RETURN_VOID, Opcode.THROW) -> emptyList()
                i.op == Opcode.GOTO -> listOf(target(i.target))
                i.op in setOf(Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH) -> (switchBranches(i).map { it.second } + listOfNotNull(next)).distinct()
                i.op.name.startsWith("IF_") -> (listOf(target(i.target)) + listOfNotNull(next)).distinct()
                i.op.name.endsWith("_PAYLOAD") -> emptyList()
                else -> listOfNotNull(next)
            }
        }
        val edges = insns.indices.associateWith(::successors)
        val exceptionEdges = insns.indices.associateWith { index ->
            reader.tries.filter { insns[index].offset in it.startOffset..it.endOffset }.flatMap {
                (it.catch.handlers.toList() + it.catch.catchAllHandler).filter { offset -> offset >= 0 }.map(::target)
            }.distinct()
        }
        fun reachableCalls(start: Int): Set<Int> {
            val queue = ArrayDeque<Int>(); val seen = mutableSetOf<Int>(); val calls = mutableSetOf<Int>(); queue += start
            while (queue.isNotEmpty()) {
                val index = queue.removeFirst(); if (!seen.add(index)) continue
                val i = insns[index]; if (i.method != null && i.op.name.startsWith("INVOKE_")) calls += i.offset
                queue.addAll(edges[index].orEmpty()); queue.addAll(exceptionEdges[index].orEmpty())
            }
            return calls
        }
        val reachCache = mutableMapOf<Int, Set<Int>>()
        val paths = mutableListOf<RawTrace>(); val unknown = linkedSetOf<SliceUncertainty>()
        fun incomplete(state: State, reason: String) {
            unknown += SliceUncertainty(insns[state.index].offset, reason,
                state.calls.map { it.offset }.toSet() + reachCache.getOrPut(state.index) { reachableCalls(state.index) })
            paths += RawTrace(false, reason, state.calls, state.writes, emptyList(), state.constructions, state.arrayEffects)
        }
        val arguments = mutableMapOf<Int, Value>()
        val words = method.id.args.sumOf { if (it in setOf("J", "D")) 2 else 1 } + if (method.flags and 8 == 0) 1 else 0
        var reg = reader.argsStartReg.takeIf { it >= 0 } ?: reader.registersCount - words
        if (method.flags and 8 == 0) arguments[reg++] = Value.Parameter(-1, method.id.owner)
        method.id.args.forEachIndexed { n, type -> arguments[reg] = Value.Parameter(n, type); reg += if (type in setOf("J", "D")) 2 else 1 }
        val pending = ArrayDeque<State>(); pending += State(0, arguments)
        var steps = 0
        while (pending.isNotEmpty()) {
            val before = pending.removeFirst(); val i = insns[before.index]
            if (++steps > MAX_STEPS) { incomplete(before, "Call slice instruction budget exceeded"); pending.forEach { incomplete(it, "Call slice instruction budget exceeded") }; break }
            if (before.index in before.visited) { incomplete(before, "Call slice encountered a loop"); continue }
            if (i.op in setOf(Opcode.UNKNOWN, Opcode.JAVA_JSR, Opcode.JAVA_RET) || i.op.name.endsWith("_PAYLOAD")) {
                incomplete(before, "Unsupported call slice instruction ${i.op}"); continue
            }
            val regs = before.regs.toMutableMap(); var result: Value = Value.Unknown
            val fields = before.fields.toMutableMap(); val arrays = before.arrays.toMutableMap()
            val constructors = before.constructions.toMutableMap()
            val escaped = before.escapedArrays.toMutableSet(); val effects = before.arrayEffects.toMutableList()
            var call: CallEvent? = null; var write: WriteEvent? = null
            fun value(n: Int): Value = i.regs.getOrNull(n)?.let { regs[it] } ?: Value.Unknown
            fun set(v: Value) { i.regs.firstOrNull()?.let { regs[it] = v } }
            fun invalidate(root: Value) {
                val queue = ArrayDeque<Value>(); val seen = mutableSetOf<Value>(); queue += root
                while (queue.isNotEmpty()) {
                    val value = queue.removeFirst(); if (!seen.add(value)) continue
                    when (value) {
                        is Value.Array -> {
                            val old = arrays[value].orEmpty(); queue.addAll(old.values)
                            escaped += value
                            effects += ArrayEffect(i.offset, value, before.calls.map { it.offset }.toSet(), "Array or containing value escaped to an unanalysed use")
                            arrays[value] = old.mapValues { Value.Unknown } + (-1 to Value.Unknown)
                        }
                        is Value.Invocation -> queue.addAll(value.args + listOfNotNull(value.receiver))
                        is Value.FieldRead -> { value.receiver?.let(queue::add); fields[value.receiver]?.get(value.field)?.let(queue::add) }
                        is Value.Allocation -> { queue.addAll(constructors[value]?.args.orEmpty()); queue.addAll(fields[value].orEmpty().values) }
                        else -> Unit
                    }
                }
            }
            when (i.op) {
                Opcode.CONST_STRING -> set(Value.Text(i.text!!))
                Opcode.CONST_CLASS -> set(Value.ClassLiteral(i.type!!))
                Opcode.CONST, Opcode.CONST_WIDE -> set(Value.Number(i.literal))
                Opcode.MOVE, Opcode.MOVE_OBJECT, Opcode.MOVE_WIDE -> set(value(1))
                Opcode.MOVE_RESULT -> set(before.result)
                Opcode.NEW_INSTANCE -> set(Value.Allocation(i.offset, i.type!!))
                Opcode.NEW_ARRAY -> {
                    val length = (value(1) as? Value.Number)?.value
                    val array = Value.Array(i.offset)
                    arrays[array] = if (length != null && length in 0..MAX_ARRAY.toLong())
                        (0 until length.toInt()).associateWith { Value.Unknown } else mapOf(-1 to Value.Unknown)
                    set(array)
                }
                Opcode.FILLED_NEW_ARRAY, Opcode.FILLED_NEW_ARRAY_RANGE -> {
                    val array = Value.Array(i.offset); arrays[array] = i.regs.indices.associateWith(::value); result = array
                }
                Opcode.APUT, Opcode.APUT_OBJECT -> {
                    val array = value(1) as? Value.Array; val index = (value(2) as? Value.Number)?.value
                    if (array != null) {
                        effects += ArrayEffect(i.offset, array, before.calls.map { it.offset }.toSet(), "Array element write")
                        val old = arrays[array].orEmpty()
                        if (array !in escaped && index != null && index in 0..Int.MAX_VALUE.toLong() && index.toInt() in old && -1 !in old)
                            arrays[array] = old + (index.toInt() to value(0))
                        else arrays[array] = old.mapValues { Value.Unknown } + (-1 to Value.Unknown)
                    }
                }
                Opcode.AGET, Opcode.AGET_OBJECT -> {
                    val array = value(1) as? Value.Array; val index = (value(2) as? Value.Number)?.value?.toInt()
                    set(if (array == null || index == null || -1 in arrays[array].orEmpty()) Value.Unknown else arrays[array]?.get(index) ?: Value.Unknown)
                }
                Opcode.SGET -> set(Value.FieldRead(i.field!!))
                Opcode.IGET -> { val receiver = value(1); set(fields[receiver]?.get(i.field) ?: Value.FieldRead(i.field!!, receiver)) }
                Opcode.SPUT -> { write = WriteEvent(i.offset, i.field!!, null, value(0)); invalidate(value(0)) }
                Opcode.IPUT -> {
                    val receiver = value(1); write = WriteEvent(i.offset, i.field!!, receiver, value(0))
                    fields[receiver] = fields[receiver].orEmpty() + (i.field to value(0)); invalidate(value(0))
                }
                Opcode.CHECK_CAST, Opcode.RETURN, Opcode.RETURN_VOID, Opcode.THROW, Opcode.GOTO, Opcode.NOP,
                Opcode.MONITOR_ENTER, Opcode.MONITOR_EXIT, Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH -> Unit
                else -> if (i.method != null && i.op.name.startsWith("INVOKE_")) {
                    val static = i.op in setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE)
                    val receiver = if (static) null else value(0); var cursor = if (static) 0 else 1
                    val args = i.method.args.map { type -> value(cursor).also { cursor += if (type in setOf("J", "D")) 2 else 1 } }
                    call = CallEvent(i.offset, i.method, receiver, args, before.fields[receiver].orEmpty(), before.arrays, before.constructions)
                    (args + listOfNotNull(receiver)).forEach(::invalidate)
                    if (i.method.name == "<init>" && receiver != null && receiver != Value.Unknown) constructors[receiver] = call
                    result = if ((args + listOfNotNull(receiver)).any { depth(it) > 6 }) Value.CallResult(i.offset, i.method)
                        else Value.Invocation(i.offset, i.method, receiver, args)
                } else if (!i.op.name.startsWith("IF_")) {
                    if (i.op.name == "FILL_ARRAY_DATA") invalidate(value(0)) else set(Value.Unknown)
                }
            }
            val after = before.copy(regs = regs, result = result, fields = fields, arrays = arrays, constructions = constructors,
                calls = before.calls + listOfNotNull(call), writes = before.writes + listOfNotNull(write),
                escapedArrays = escaped, arrayEffects = effects, visited = before.visited + before.index)
            if (exceptionEdges[before.index].orEmpty().isNotEmpty()) {
                unknown += SliceUncertainty(i.offset, "Exception path is outside the bounded call slice",
                    before.calls.map { it.offset }.toSet() + reachCache.getOrPut(before.index) { reachableCalls(before.index) })
            }
            if (i.op in setOf(Opcode.RETURN, Opcode.RETURN_VOID, Opcode.THROW)) {
                paths += RawTrace(true, null, after.calls, after.writes,
                    if (i.op == Opcode.RETURN) listOf(ReturnEvent(i.offset, value(0))) else emptyList(), constructors, effects)
                continue
            }
            val next = when {
                i.op in setOf(Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH) -> {
                    val key = (value(0) as? Value.Number)?.value
                    if (key == null) edges.getValue(before.index) else
                        listOfNotNull(switchBranches(i).singleOrNull { it.first.toLong() == key }?.second
                            ?: (before.index + 1).takeIf { it < insns.size })
                }
                i.op.name.startsWith("IF_") -> {
                    val a = (value(0) as? Value.Number)?.value
                    val b = if (i.op.name.endsWith("Z")) 0L else (value(1) as? Value.Number)?.value
                    val branch = if (a == null || b == null) null else when (i.op.name.removeSuffix("Z")) {
                        "IF_EQ" -> a == b; "IF_NE" -> a != b; "IF_LT" -> a < b; "IF_GE" -> a >= b; "IF_GT" -> a > b; "IF_LE" -> a <= b
                        else -> null
                    }
                    when (branch) { true -> listOf(target(i.target)); false -> listOfNotNull((before.index + 1).takeIf { it < insns.size }); null -> edges.getValue(before.index) }
                }
                else -> edges.getValue(before.index)
            }
            if (next.isEmpty()) incomplete(after, "Call slice fell through without a return")
            else if (pending.size + paths.size + next.size > MAX_PATHS) incomplete(after, "Call slice path budget exceeded")
            else next.forEach { pending += after.copy(index = it) }
        }
        return CallSliceResult(paths, unknown.toList())
    }
    private fun depth(value: Value): Int = when (value) {
        is Value.Invocation -> 1 + (value.args + listOfNotNull(value.receiver)).maxOfOrNull(::depth).orZero()
        is Value.FieldRead -> 1 + (value.receiver?.let(::depth) ?: 0)
        else -> 0
    }
    private fun Int?.orZero() = this ?: 0
}
