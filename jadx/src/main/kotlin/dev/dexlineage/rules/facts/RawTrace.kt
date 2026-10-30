package dev.dexlineage.rules.facts

import jadx.api.plugins.input.insns.InsnIndexType
import jadx.api.plugins.input.insns.Opcode
import dev.dexlineage.rules.facts.DexFactSession.*

/** Bounded, conservative local value flow. Unsupported control flow never supplies definite facts. */
internal sealed interface Value {
    data object Unknown : Value
    data class Text(val value: String) : Value
    data class Number(val value: Long) : Value
    data class Parameter(val index: Int, val type: String) : Value
    data class Allocation(val site: Int, val type: String) : Value
    data class Array(val site: Int) : Value
    data class FieldRead(val field: Field, val receiver: Value? = null) : Value
    data class Invocation(val site: Int, val method: MethodId, val receiver: Value?, val args: List<Value>) : Value
}
internal data class CallEvent(val offset: Int, val method: MethodId, val receiver: Value?, val args: List<Value>,
    val fields: Map<Field, Value>, val arrays: Map<Value.Array, Map<Int, Value>>, val constructions: Map<Value, CallEvent>)
internal data class WriteEvent(val offset: Int, val field: Field, val receiver: Value?, val value: Value)
internal data class ReturnEvent(val offset: Int, val value: Value)
internal data class RawTrace(val complete: Boolean, val reason: String?, val calls: List<CallEvent>, val writes: List<WriteEvent>,
    val returns: List<ReturnEvent>, val constructions: Map<Value, CallEvent>) {
    companion object {
        private data class Insn(val op: Opcode, val offset: Int, val regs: List<Int>, val resultReg: Int,
            val literal: Long, val target: Int, val text: String?, val type: String?, val method: MethodId?, val field: Field?)
        private data class State(val registers: Map<Int, Value>, val result: Value = Value.Unknown,
            val fields: Map<Value, Map<Field, Value>> = emptyMap(), val arrays: Map<Value.Array, Map<Int, Value>> = emptyMap(),
            val constructors: Map<Value, CallEvent> = emptyMap())
        fun read(method: Method): RawTrace {
            val reader = method.code ?: return RawTrace(false, "Method has no readable body", emptyList(), emptyList(), emptyList(), emptyMap())
            val insns = mutableListOf<Insn>()
            reader.visitInstructions { i ->
                i.decode()
                val m = if (i.indexType == InsnIndexType.METHOD_REF) i.indexAsMethod.also { it.load() } else null
                val f = if (i.indexType == InsnIndexType.FIELD_REF) i.indexAsField else null
                insns += Insn(i.opcode, i.offset, (0 until i.regsCount).map(i::getReg), i.resultReg,
                    i.literal, i.target, if (i.opcode == Opcode.CONST_STRING) i.indexAsString else null,
                    if (i.indexType == InsnIndexType.TYPE_REF) i.indexAsType else null,
                    m?.let { MethodId(it.parentClassType, it.name, it.argTypes.toList(), it.returnType) },
                    f?.let { Field(it.parentClassType, it.name, it.type) })
            }
            if (insns.isEmpty()) return RawTrace(false, "Empty method body", emptyList(), emptyList(), emptyList(), emptyMap())
            if (insns.any { it.op in setOf(Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH, Opcode.JAVA_JSR, Opcode.JAVA_RET, Opcode.UNKNOWN) })
                return RawTrace(false, "Unsupported switch or control-flow instruction", emptyList(), emptyList(), emptyList(), emptyMap())
            val indices = insns.mapIndexed { index, insn -> insn.offset to index }.toMap()
            val arguments = mutableMapOf<Int, Value>()
            // The DEX reader reports -1 for argsStartReg; DEX input arguments occupy the final registers.
            val argumentWords = method.id.args.sumOf { if (it in setOf("J", "D")) 2 else 1 } + if (method.flags and 8 == 0) 1 else 0
            var reg = reader.argsStartReg.takeIf { it >= 0 } ?: (reader.registersCount - argumentWords)
            if (method.flags and 8 == 0) arguments[reg++] = Value.Parameter(-1, method.id.owner)
            method.id.args.forEachIndexed { index, type -> arguments[reg] = Value.Parameter(index, type); reg += if (type in setOf("J", "D")) 2 else 1 }
            val states = mutableMapOf(0 to State(arguments)); val queue = ArrayDeque<Int>(); queue += 0
            var operations = 0
            fun merge(a: State, b: State): State {
                fun values(a: Map<Int, Value>, b: Map<Int, Value>) = (a.keys + b.keys).associateWith { if (a[it] == b[it]) a[it] ?: Value.Unknown else Value.Unknown }
                val fields = (a.fields.keys + b.fields.keys).associateWith { objectId ->
                    val left = a.fields[objectId].orEmpty(); val right = b.fields[objectId].orEmpty()
                    (left.keys + right.keys).associateWith { if (left[it] == right[it]) left[it] ?: Value.Unknown else Value.Unknown }
                }
                val arrays = (a.arrays.keys + b.arrays.keys).associateWith { values(a.arrays[it].orEmpty(), b.arrays[it].orEmpty()) }
                return State(values(a.registers, b.registers), if (a.result == b.result) a.result else Value.Unknown, fields, arrays,
                    a.constructors.filter { (key, value) -> b.constructors[key] == value })
            }
            fun step(i: Insn, before: State): Triple<State, CallEvent?, WriteEvent?> {
                val regs = before.registers.toMutableMap(); var result: Value = Value.Unknown
                val fields = before.fields.toMutableMap(); val arrays = before.arrays.toMutableMap(); val constructors = before.constructors.toMutableMap()
                fun value(index: Int) = i.regs.getOrNull(index)?.let { regs[it] } ?: Value.Unknown
                fun set(value: Value) { if (i.regs.isNotEmpty()) regs[i.regs[0]] = value }
                fun invalidateArray(root: Value) {
                    val pending = ArrayDeque<Value.Array>(); val seen = mutableSetOf<Value.Array>()
                    (root as? Value.Array)?.let(pending::add)
                    while (pending.isNotEmpty()) {
                        val array = pending.removeFirst(); if (!seen.add(array)) continue
                        val elements = arrays[array].orEmpty()
                        elements.values.filterIsInstance<Value.Array>().forEach(pending::add)
                        arrays[array] = elements.mapValues { Value.Unknown }
                    }
                }
                var call: CallEvent? = null; var write: WriteEvent? = null
                when (i.op) {
                    Opcode.CONST_STRING -> set(Value.Text(i.text!!))
                    Opcode.CONST, Opcode.CONST_WIDE -> set(Value.Number(i.literal))
                    Opcode.MOVE, Opcode.MOVE_OBJECT, Opcode.MOVE_WIDE -> set(value(1))
                    Opcode.MOVE_RESULT -> set(before.result)
                    Opcode.NEW_INSTANCE -> set(Value.Allocation(i.offset, i.type!!))
                    Opcode.NEW_ARRAY -> { val array = Value.Array(i.offset); arrays[array] = emptyMap(); set(array) }
                    Opcode.FILLED_NEW_ARRAY, Opcode.FILLED_NEW_ARRAY_RANGE -> {
                        val array = Value.Array(i.offset); arrays[array] = i.regs.indices.associateWith(::value); result = array
                    }
                    Opcode.APUT_OBJECT, Opcode.APUT -> {
                        val array = value(1) as? Value.Array; val index = (value(2) as? Value.Number)?.value?.toInt()
                        if (array != null && index != null) arrays[array] = arrays[array].orEmpty() + (index to value(0))
                    }
                    Opcode.AGET_OBJECT, Opcode.AGET -> {
                        val array = value(1) as? Value.Array; val index = (value(2) as? Value.Number)?.value?.toInt()
                        set(if (array == null || index == null) Value.Unknown else arrays[array]?.get(index) ?: Value.Unknown)
                    }
                    Opcode.SGET -> set(Value.FieldRead(i.field!!))
                    Opcode.IGET -> { val receiver = value(1); set(fields[receiver]?.get(i.field) ?: Value.FieldRead(i.field!!, receiver)) }
                    Opcode.SPUT -> { write = WriteEvent(i.offset, i.field!!, null, value(0)); invalidateArray(value(0)) }
                    Opcode.IPUT -> { val receiver = value(1); write = WriteEvent(i.offset, i.field!!, receiver, value(0)); fields[receiver] = fields[receiver].orEmpty() + (i.field to value(0)); invalidateArray(value(0)) }
                    Opcode.CHECK_CAST -> Unit
                    Opcode.RETURN, Opcode.RETURN_VOID, Opcode.THROW, Opcode.GOTO, Opcode.NOP,
                    Opcode.MONITOR_ENTER, Opcode.MONITOR_EXIT -> Unit
                    else -> {
                        if (i.method != null && i.op.name.startsWith("INVOKE_")) {
                            val static = i.op in setOf(Opcode.INVOKE_STATIC, Opcode.INVOKE_STATIC_RANGE)
                            val receiver = if (static) null else value(0); var cursor = if (static) 0 else 1
                            val args = i.method.args.map { type -> value(cursor).also { cursor += if (type in setOf("J", "D")) 2 else 1 } }
                            call = CallEvent(i.offset, i.method, receiver, args, before.fields[receiver].orEmpty(), before.arrays, emptyMap())
                            // The call sees the pre-call values. Subsequent uses cannot assume an escaped
                            // mutable array was preserved by an unanalysed callee (including nested arrays).
                            (args + listOfNotNull(receiver)).forEach(::invalidateArray)
                            // Constructor metadata is deliberately shallow, keeping the abstract domain finite.
                            if (i.method.name == "<init>" && receiver != Value.Unknown && receiver != null) constructors[receiver] = call
                            result = if (args.any { depth(it) > 6 } || (receiver?.let(::depth) ?: 0) > 6) Value.Unknown
                                else Value.Invocation(i.offset, i.method, receiver, args)
                        } else if (!i.op.name.startsWith("IF") && i.regs.isNotEmpty()) regs[i.regs[0]] = Value.Unknown
                    }
                }
                return Triple(State(regs, result, fields, arrays, constructors), call?.copy(constructions = before.constructors), write)
            }
            while (queue.isNotEmpty()) {
                if (++operations > maxOf(2000, insns.size * 30)) return RawTrace(false, "Local data-flow iteration budget exceeded", emptyList(), emptyList(), emptyList(), emptyMap())
                val index = queue.removeFirst(); val i = insns[index]; val before = states.getValue(index); val after = step(i, before).first
                val successors = when {
                    i.op in setOf(Opcode.RETURN, Opcode.RETURN_VOID, Opcode.THROW) -> emptyList()
                    i.op == Opcode.GOTO -> listOfNotNull(indices[i.target])
                    i.op.name.startsWith("IF") -> listOfNotNull((index + 1).takeIf { it < insns.size }, indices[i.target])
                    else -> listOfNotNull((index + 1).takeIf { it < insns.size })
                }.toMutableSet()
                reader.tries.filter { i.offset in it.startOffset..it.endOffset }.forEach { attempt ->
                    (attempt.catch.handlers.toList() + attempt.catch.catchAllHandler).filter { it >= 0 }.mapNotNull(indices::get).forEach(successors::add)
                }
                successors.forEach { next ->
                    val old = states[next]; val merged = if (old == null) after else merge(old, after)
                    if (old != merged) { states[next] = merged; if (next !in queue) queue += next }
                }
            }
            val calls = mutableListOf<CallEvent>(); val writes = mutableListOf<WriteEvent>(); val returns = mutableListOf<ReturnEvent>(); val constructors = mutableMapOf<Value, CallEvent>()
            states.toSortedMap().forEach { (index, state) ->
                val i = insns[index]; val (after, call, write) = step(i, state)
                call?.let(calls::add); write?.let(writes::add); constructors.putAll(after.constructors)
                if (i.op == Opcode.RETURN) returns += ReturnEvent(i.offset, state.registers[i.regs[0]] ?: Value.Unknown)
            }
            return RawTrace(true, null, calls, writes, returns, constructors)
        }
        private fun depth(value: Value): Int = when(value) {
            is Value.Invocation -> 1 + (value.args + listOfNotNull(value.receiver)).maxOfOrNull(::depth).orZero()
            is Value.FieldRead -> 1 + (value.receiver?.let(::depth) ?: 0)
            else -> 0
        }
        private fun Int?.orZero() = this ?: 0
    }
}
