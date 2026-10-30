package dev.dexlineage.apk

import dev.dexlineage.io.Digests
import dev.dexlineage.io.ExecutionException
import dev.dexlineage.io.ValidationException
import dev.dexlineage.model.Artifact
import dev.dexlineage.model.ClassRef
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.assertFailsWith

class ApkResearchReaderTest {
    @TempDir lateinit var temporary: Path

    @Test fun `foreign research references fail before APK facts can be read`() {
        assertFailsWith<ValidationException> {
            ApkResearchReader.read(Artifact("not-opened.apk", "expected"), listOf(ClassRef("foreign", "La;", "classes.dex")))
        }
    }

    @Test fun `malformed raw DEX is an execution failure rather than empty research`() {
        val path = temporary.resolve("invalid.apk")
        ZipOutputStream(Files.newOutputStream(path)).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml")); zip.write(byteArrayOf(0)); zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex")); zip.write(byteArrayOf(0, 1, 2)); zip.closeEntry()
        }
        val apk = Digests.artifact(path)
        assertFailsWith<ExecutionException> {
            ApkResearchReader.read(apk, listOf(ClassRef(apk.sha256, "La;", "classes.dex")))
        }
    }
}
