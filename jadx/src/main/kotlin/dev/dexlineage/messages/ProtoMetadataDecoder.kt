package dev.dexlineage.messages

import dev.dexlineage.model.ClassRef
import dev.dexlineage.rules.facts.DexFactSession.Field

/**
 * A deliberately finite reader of protobuf-lite's proto3 RawMessageInfo format.
 * Format reference: protocolbuffers/protobuf v25.3, RawMessageInfo and MessageSchema.
 * This reads schema facts only; it does not execute protobuf code or interpret payloads.
 */
internal object ProtoMetadataDecoder {
    data class FieldInfo(val number: Int, val cardinality: String, val kind: String,
        val field: Field, val typeId: Int, val child: ClassRef?)
    data class Result(val fields: List<FieldInfo>, val problem: String? = null)

    fun decode(info: String, objects: List<ProtoMetadataObject>, fields: List<Field>,
        messageBase: String, resolve: (String) -> ClassRef?, isSubtype: (String, String) -> Boolean): Result = try {
        Result(read(info, objects, fields, messageBase, resolve, isSubtype))
    } catch (e: UnsupportedMetadata) { Result(emptyList(), e.message!!) }

    private class UnsupportedMetadata(message: String) : RuntimeException(message)
    private fun need(value: Boolean, reason: String) { if (!value) throw UnsupportedMetadata(reason) }

    private class Integers(private val text: String) {
        var position = 0
        fun next(): Int {
            var result = 0L; var shift = 0
            repeat(3) {
                need(position < text.length, "Truncated compact metadata integer")
                val c = text[position++].code
                need(c !in 0xD800..0xDFFF, "Surrogate character in compact metadata integer")
                if (c < 0xD800) {
                    result = result or (c.toLong() shl shift)
                    need(result <= Int.MAX_VALUE, "Compact metadata integer overflow")
                    return result.toInt()
                }
                result = result or ((c and 0x1FFF).toLong() shl shift); shift += 13
            }
            throw UnsupportedMetadata("Overlong compact metadata integer")
        }
        fun done() = position == text.length
    }

    private fun read(info: String, objects: List<ProtoMetadataObject>, fields: List<Field>,
        messageBase: String, resolve: (String) -> ClassRef?, isSubtype: (String, String) -> Boolean): List<FieldInfo> {
        val ints = Integers(info)
        need(ints.next() == 0, "Only proto3 metadata without message-set or edition flags is supported")
        val count = ints.next()
        need(count <= 100_000, "Metadata field count exceeds the bounded reader")
        need(objects.map { it.index } == objects.indices.toList(), "Metadata Object[] is not a complete contiguous snapshot")
        if (count == 0) { need(ints.done() && objects.isEmpty(), "Empty message has trailing metadata"); return emptyList() }
        val oneofs = ints.next(); val hasBits = ints.next(); val min = ints.next(); val max = ints.next()
        val entries = ints.next(); val maps = ints.next(); val repeated = ints.next(); val checked = ints.next()
        need(oneofs == 0 && maps == 0, "Oneof and map metadata are outside this slice")
        need(entries == count && hasBits <= objects.size, "Metadata header counts are inconsistent")
        need(min in 1..536870911 && max in min..536870911, "Invalid metadata field range")
        val byName = fields.filter { it.flags and 8 == 0 }.groupBy { it.name }
        fun declared(name: String): Field {
            val found = byName[name].orEmpty()
            need(found.size == 1, "Metadata field name does not identify one instance field: $name")
            return found.single()
        }
        fun fieldObject(index: Int): Field {
            need(index in objects.indices, "Metadata Object[] cursor overflow")
            val value = objects[index]
            need(value.kind == "STRING" && !value.text.isNullOrBlank(), "Metadata field reference is not a constant string")
            return declared(value.text!!)
        }
        val presence = (0 until hasBits).map { fieldObject(it) }
        need(presence.all { it.type == "I" } && presence.map { it.name }.distinct().size == presence.size, "Invalid metadata presence fields")
        var cursor = hasBits; var repeatedSeen = 0; var checkedSeen = 0
        val usedFields = mutableSetOf<String>(); val numbers = mutableSetOf<Int>(); val result = mutableListOf<FieldInfo>()
        repeat(count) {
            val number = ints.next(); val bits = ints.next(); val type = bits and 0xFF
            need(number in 1..536870911 && numbers.add(number), "Invalid or duplicate protobuf field number")
            need(bits and 0x1FFF.inv() == 0 && bits and (0x100 or 0x800) == 0, "Unsupported protobuf field feature bits")
            need(type in 0..48 && type !in setOf(10, 17, 28), "Unsupported bytes, oneof, map, group or unknown protobuf field type")
            if (bits and 0x400 != 0) checkedSeen++
            val field = fieldObject(cursor++)
            need(usedFields.add(field.name) && field.name !in presence.map { it.name }, "Metadata reuses an instance field for incompatible roles")
            val list = type >= 18
            if (list) repeatedSeen++
            val hasPresence = bits and 0x1000 != 0
            need(!hasPresence || !list, "Repeated field cannot carry a singular presence index")
            if (hasPresence) need(ints.next() < hasBits * 32, "Metadata presence bit is outside the declared fields")
            val child = when (type) {
                9 -> {
                    need(field.type.startsWith("L") && isSubtype(field.type, messageBase), "Singular message field has an incompatible declared type")
                    resolve(field.type) ?: throw UnsupportedMetadata("Singular message type is absent from APK")
                }
                27 -> {
                    need(cursor in objects.indices, "Repeated message class literal is missing")
                    val value = objects[cursor++]
                    need(value.kind == "CLASS" && value.type != null && isSubtype(value.type, messageBase), "Repeated message element is not a compatible class literal")
                    resolve(value.type!!) ?: throw UnsupportedMetadata("Repeated message type is absent from APK")
                }
                else -> null
            }
            if (list) need(isSubtype(field.type, "Ljava/util/List;"), "Repeated metadata field is not a List type")
            else if (type != 9) need(scalarCompatible(type, field.type), "Scalar metadata and field descriptor disagree")
            result += FieldInfo(number, if (list) "repeated" else "singular", if (child == null) "scalar" else "message", field, type, child)
        }
        need(ints.done() && cursor == objects.size, "Metadata has unconsumed integers or objects")
        need(numbers.min() == min && numbers.max() == max && repeatedSeen == repeated && checkedSeen == checked,
            "Metadata range or repeated/check counts disagree with entries")
        return result
    }

    private fun scalarCompatible(type: Int, descriptor: String): Boolean = when (type) {
        0 -> descriptor == "D"
        1 -> descriptor == "F"
        2, 3, 5, 14, 16 -> descriptor == "J"
        4, 6, 11, 12, 13, 15 -> descriptor == "I"
        7 -> descriptor == "Z"
        8 -> descriptor == "Ljava/lang/String;"
        else -> false
    }
}
