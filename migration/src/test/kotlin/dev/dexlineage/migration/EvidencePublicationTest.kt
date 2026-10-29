package dev.dexlineage.migration

import dev.dexlineage.io.*
import dev.dexlineage.knowledge.EvidenceFiles
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class EvidencePublicationTest {
    @TempDir lateinit var temp: Path

    private fun setup(): Pair<Artifact, ClassRef> {
        val file = temp.resolve("input-bytes")
        Files.writeString(file, "original bytes")
        val artifact = Digests.artifact(file)
        val ref = ClassRef(artifact.sha256, "La;", "classes.dex")
        return artifact to ref
    }
    private fun code() = listOf(DecompiledClass("La;", "class a {}", null, false, emptyList(), 1))

    @Test fun `changed APK is rejected before any evidence is published`() {
        val (artifact, ref) = setup()
        Files.writeString(Path.of(artifact.path), "replaced input")
        assertFailsWith<ValidationException> { EvidenceFiles.publish(temp, "r", artifact, listOf(ref), code()) }
        assertFalse(Files.exists(temp.resolve("evidence")))
    }
    @Test fun `interrupted staging does not obstruct publication and cached files are verified`() {
        val (artifact, ref) = setup()
        val interrupted = temp.resolve("evidence/.pending-interrupted")
        Files.createDirectories(interrupted)
        Files.writeString(interrupted.resolve("code.java"), "partial")
        val record = EvidenceFiles.publish(temp, "r", artifact, listOf(ref), code()).single()
        assertEquals(record, EvidenceFiles.read(temp, "r", record.evidenceId))
        assertEquals(record, EvidenceFiles.publish(temp, "r", artifact, listOf(ref), code()).single())
        assertTrue(Files.exists(interrupted))
        Files.writeString(temp.resolve(record.javaPath), "changed")
        assertFailsWith<ValidationException> { EvidenceFiles.read(temp, "r", record.evidenceId) }
    }
}
