package dev.dexlineage.messages

import com.google.gson.JsonParser
import dev.dexlineage.io.ValidationException
import dev.dexlineage.knowledge.RuleProofs
import dev.dexlineage.model.*
import dev.dexlineage.rules.StrategyRegistry
import dev.dexlineage.rules.facts.DexFactSession.Field
import org.junit.jupiter.api.Test
import kotlin.test.*

class ProtoMetadataDecoderTest {
    private val hash = "a".repeat(64)
    private val fields = listOf(Field("Lparent;", "bits", "I"), Field("Lparent;", "request", "Lchild;"),
        Field("Lparent;", "items", "Llist;"), Field("Lparent;", "noise", "I"), Field("Lparent;", "text", "Ljava/lang/String;"))
    private fun text(index: Int, value: String) = ProtoMetadataObject(index, "STRING", text = value)
    private fun klass(index: Int, value: String) = ProtoMetadataObject(index, "CLASS", type = value)
    private val objects = listOf(text(0, "bits"), text(1, "request"), text(2, "items"), klass(3, "Litem;"))
    private fun encode(vararg values: Int): String = buildString {
        values.forEach { number ->
            var n = number
            while (n >= 0xD800) { append(((n and 0x1FFF) or 0xE000).toChar()); n = n ushr 13 }
            append(n.toChar())
        }
    }
    private val info = encode(0, 2, 0, 1, 1, 2, 2, 0, 1, 0, 1, 0x1009, 0, 2, 27)
    private fun decode(info: String = this.info, objects: List<ProtoMetadataObject> = this.objects, fields: List<Field> = this.fields) =
        ProtoMetadataDecoder.decode(info, objects, fields, "Lmessage;", { type ->
            if (type in setOf("Lchild;", "Litem;", "Lother;")) ClassRef(hash, type, "classes.dex") else null
        }, { type, base -> if (base == "Ljava/util/List;") type == "Llist;" else type in setOf("Lchild;", "Litem;", "Lother;") })

    @Test fun `singular declared type and repeated class literal are separate roles`() {
        val result = decode()
        assertNull(result.problem)
        assertEquals(listOf(1, 2), result.fields.map { it.number })
        assertEquals(listOf("singular", "repeated"), result.fields.map { it.cardinality })
        assertEquals(listOf("Lchild;", "Litem;"), result.fields.map { it.child!!.descriptor })
    }

    @Test fun `field storage order and irrelevant scalar position do not determine type`() {
        val reordered = encode(0, 3, 0, 1, 1, 7, 3, 0, 1, 0, 7, 4, 2, 27, 1, 0x1009, 0)
        val values = listOf(text(0, "bits"), text(1, "noise"), text(2, "items"), klass(3, "Litem;"), text(4, "request"))
        val result = decode(reordered, values, fields.reversed())
        assertNull(result.problem)
        assertEquals("Lchild;", result.fields.single { it.number == 1 }.child!!.descriptor)
        assertEquals("Litem;", result.fields.single { it.number == 2 }.child!!.descriptor)
        assertEquals("scalar", result.fields.single { it.number == 7 }.kind)
    }

    @Test fun `complete cursor is mandatory no usable prefix after unsupported metadata`() {
        val failures = listOf(
            info + encode(3, 4), info.dropLast(1), encode(1, 0), encode(4, 0),
            encode(0, 2, 1, 1, 1, 2, 2, 0, 1, 0, 1, 9, 2, 27),
            encode(0, 2, 0, 1, 1, 2, 2, 1, 1, 0, 1, 9, 2, 27),
            encode(0, 2, 0, 1, 1, 2, 2, 0, 1, 0, 1, 0x1009, 0, 1, 27),
            encode(0, 2, 0, 1, 1, 2, 2, 0, 1, 0, 1, 0x1009, 32, 2, 27),
            encode(0, 2, 0, 1, 1, 2, 2, 0, 1, 0, 1, 0x1009, 0, 2, 49),
            encode(0, 2, 0, 1, 1, 2, 2, 0, 0, 0, 1, 0x1009, 0, 2, 10))
        failures.forEach { damaged -> val result = decode(damaged); assertNotNull(result.problem); assertTrue(result.fields.isEmpty()) }
    }

    @Test fun `objects cannot be borrowed from another field or call`() {
        val bad = listOf(
            objects.dropLast(1), objects + text(4, "noise"), objects.map { if (it.index == 3) it.copy(kind = "UNKNOWN", type = null) else it },
            objects.map { if (it.index == 1) it.copy(text = "noise") else it },
            objects.map { if (it.index == 2) it.copy(text = "absent") else it },
            objects.map { if (it.index == 3) klass(3, "Lmissing;") else it })
        bad.forEach { values -> val result = decode(objects = values); assertNotNull(result.problem); assertTrue(result.fields.isEmpty()) }
    }

    @Test fun `compact integers validate continuation overflow and field range`() {
        val large = encode(0, 1, 0, 0, 100_000, 100_000, 1, 0, 0, 0, 100_000, 9)
        assertNull(decode(large, listOf(text(0, "request"))).problem)
        listOf("\uD800\u0000", "\uE000", "\uFFFF\uFFFF\uFFFF\u0000", encode(0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 9)).forEach {
            assertNotNull(decode(it).problem)
        }
    }

    @Test fun `empty supported message is complete and has no message edge`() {
        val result = decode(encode(0, 0), emptyList())
        assertNull(result.problem); assertTrue(result.fields.isEmpty())
    }

    @Test fun `selector requires a positive number and a supported cardinality`() {
        fun rule(params: String) = RuleProofs.revision(emptyList(), StrategySpec("messages.proto-field-type",
            JsonParser.parseString(params).asJsonObject, EntityKind.CLASS, mapOf("parent" to "parent")))
        StrategyRegistry.validate(rule("{\"fieldNumber\":1,\"cardinality\":\"singular\"}"))
        listOf("{\"fieldNumber\":0,\"cardinality\":\"singular\"}", "{\"fieldNumber\":\"1\",\"cardinality\":\"singular\"}",
            "{\"fieldNumber\":2,\"cardinality\":\"map\"}", "{\"fieldNumber\":2,\"cardinality\":\"repeated\",\"expectedClass\":\"Lchild;\"}")
            .forEach { assertFailsWith<ValidationException> { StrategyRegistry.validate(rule(it)) } }
    }
}
