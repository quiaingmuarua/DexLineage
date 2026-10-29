package dev.dexlineage.mapping

import dev.dexlineage.io.ValidationException
import dev.dexlineage.model.AcceptedRename
import net.fabricmc.mappingio.MappingReader
import net.fabricmc.mappingio.tree.MemoryMappingTree
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MappingTests {
    @TempDir lateinit var temp: Path

    @Test fun `class mappings round trip default packaged and inner identities`() {
        val path = temp.resolve("mapping.tiny")
        val renames = listOf(
            AcceptedRename("Lx/y/Outer\$Inner;", "x.y.ReadableInner"),
            AcceptedRename("Lx/y/a;", "x.y.ReadableClass"),
            AcceptedRename("La;", "ReadableDefault"),
        )
        MappingOutput.write(path, renames)
        MappingOutput.verifyContents(path, renames)
        val tree = MemoryMappingTree()
        MappingReader.read(path, tree)
        assertEquals("obfuscated", tree.srcNamespace)
        assertEquals(listOf("named"), tree.dstNamespaces)
        assertEquals("ReadableDefault", tree.getClass("a")!!.getDstName(0))
        assertEquals("x/y/ReadableInner", tree.getClass("x/y/Outer\$Inner")!!.getDstName(0))
        assertTrue(tree.classes.all { it.fields.isEmpty() && it.methods.isEmpty() })
    }

    @Test fun `input order does not change mapping bytes`() {
        val a = AcceptedRename("La;", "ReadableA")
        val b = AcceptedRename("Lb;", "ReadableB")
        MappingOutput.write(temp.resolve("first.tiny"), listOf(b, a))
        MappingOutput.write(temp.resolve("second.tiny"), listOf(a, b))
        assertEquals(Files.readString(temp.resolve("first.tiny")), Files.readString(temp.resolve("second.tiny")))
    }

    @Test fun `mapping files are never overwritten`() {
        val path = temp.resolve("existing.tiny")
        Files.writeString(path, "preserve me")
        assertFailsWith<ValidationException> { MappingOutput.write(path, emptyList()) }
        assertEquals("preserve me", Files.readString(path))
    }

    @Test fun `duplicate identities or names are rejected before creating output`() {
        val path = temp.resolve("invalid.tiny")
        assertFailsWith<ValidationException> {
            MappingOutput.write(path, listOf(AcceptedRename("La;", "First"), AcceptedRename("La;", "Second")))
        }
        assertFailsWith<ValidationException> {
            MappingOutput.write(path, listOf(AcceptedRename("La;", "Same"), AcceptedRename("Lb;", "Same")))
        }
        assertFalse(Files.exists(path))
    }

    @Test fun `invalid names cannot inject mapping records`() {
        for (name in listOf("", "a..b", "a/b", "a\nInjected", "9Class")) {
            val path = temp.resolve("invalid-name.tiny")
            assertFailsWith<ValidationException> { MappingOutput.write(path, listOf(AcceptedRename("La;", name))) }
            assertFalse(Files.exists(path))
        }
    }

    @Test fun `zero accepted entries produce a valid empty mapping`() {
        val path = temp.resolve("empty.tiny")
        MappingOutput.write(path, emptyList())
        MappingOutput.verifyContents(path, emptyList())
        assertEquals("tiny\t2\t0\tobfuscated\tnamed", Files.readString(path).trim())
    }

    @Test fun `unexpected classes namespaces or members fail verification`() {
        val path = temp.resolve("unexpected.tiny")
        MappingOutput.write(path, listOf(AcceptedRename("La;", "A")))
        assertFailsWith<ValidationException> { MappingOutput.verifyContents(path, emptyList()) }
        Files.writeString(path, "tiny\t2\t0\tobfuscated\tnamed\nc\ta\tA\n\tf\tI\tx\ty\n")
        assertFailsWith<ValidationException> { MappingOutput.verifyContents(path, listOf(AcceptedRename("La;", "A"))) }
        Files.writeString(path, "tiny\t2\t0\tother\tnamed\nc\ta\tA\n")
        assertFailsWith<ValidationException> { MappingOutput.verifyContents(path, listOf(AcceptedRename("La;", "A"))) }
    }
}
