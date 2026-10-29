package dev.dexlineage.apk

import dev.dexlineage.io.ExecutionException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class ApkReaderTest {
    @TempDir lateinit var dir: Path

    @Test fun `resource-only archive is not reported as a successful empty scan`() {
        val path = archive("resource-only.zip", "AndroidManifest.xml", "not a DEX".toByteArray())
        assertFailsWith<ExecutionException> { ApkReader.scan(path, setOf("anchor")) }
    }

    @Test fun `broken dex exposes incomplete scan diagnostics`() {
        val result = ApkReader.scan(archive("broken.zip", "classes.dex", byteArrayOf(1, 2, 3)), setOf("anchor"))
        assertTrue(result.stats.diagnostics.any { "Truncated DEX header" in it })
        assertEquals(emptyList(), result.uses["anchor"])
    }

    @Test fun `placeholder is incomplete even with zero errors`() {
        val messages = ApkReader.codeDiagnostics(
            "throw new UnsupportedOperationException(\"Method not decompiled: a.b():void\");", 0, 0,
        )
        assertTrue(messages.any { "placeholder" in it })
    }

    @Test fun `warnings are retained without hiding readable source`() {
        assertTrue(ApkReader.codeDiagnostics("class A {}", 0, 1).isNotEmpty())
        assertTrue(ApkReader.codeDiagnostics("class A {}", 0, 0).isEmpty())
    }

    private fun archive(name: String, entry: String, contents: ByteArray): Path = dir.resolve(name).also { path ->
        ZipOutputStream(path.toFile().outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry(entry))
            zip.write(contents)
            zip.closeEntry()
        }
    }
}
