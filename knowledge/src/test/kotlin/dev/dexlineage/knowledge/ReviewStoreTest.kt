package dev.dexlineage.knowledge

import dev.dexlineage.io.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.test.*

class ReviewStoreTest {
    @TempDir lateinit var directory: Path
    @Test fun `invalid later revision leaves whole batch unwritten`() {
        val first = ReviewStore.submit(directory, "run", "one", null, mapOf("action" to "DEFER"))
        assertFailsWith<ValidationException> {
            ReviewStore.submitBatch(directory, "run", listOf(
                ReviewRequest("two", null, mapOf("action" to "ACCEPT")),
                ReviewRequest("one", "wrong", mapOf("action" to "ACCEPT"))))
        }
        assertEquals(mapOf("one" to first), ReviewStore.latest(directory, "run"))
    }
    @Test fun `retries are idempotent explicit replacement retains history and snapshot`() {
        val requests = listOf(ReviewRequest("one", null, mapOf("action" to "DEFER")), ReviewRequest("two", null, mapOf("action" to "REJECT")))
        val first = ReviewStore.submitBatch(directory, "run", requests)
        assertEquals(first, ReviewStore.submitBatch(directory, "run", requests))
        val snapshot = directory.resolve("report.json")
        JsonFiles.writeNew(snapshot, mapOf("schemaVersion" to SCHEMA_VERSION, "runId" to "run", "reviewRevisions" to first.associate { it.taskId to it.revisionId }))
        val revised = ReviewStore.submit(directory, "run", "one", first[0].revisionId, mapOf("action" to "ACCEPT"))
        assertEquals(revised, ReviewStore.latest(directory, "run")["one"])
        assertEquals(first.associateBy { it.taskId }, ReviewStore.fromSnapshot(directory, "run", snapshot))
        assertEquals(first, ReviewStore.submitBatch(directory, "run", requests))
        assertEquals(revised, ReviewStore.latest(directory, "run")["one"])
        assertFailsWith<ValidationException> { ReviewStore.fromSnapshot(directory, "another-run", snapshot) }
    }
    @Test fun `same target and name collisions reject whole groups`() {
        assertEquals(setOf("one", "two"), NameChecks.conflicts(mapOf("one" to AcceptedRename("La;", "Name"), "two" to AcceptedRename("Lb;", "Name")), setOf("La;", "Lb;")).keys)
        assertEquals(setOf("one", "two"), NameChecks.conflicts(mapOf("one" to AcceptedRename("La;", "One"), "two" to AcceptedRename("La;", "Two")), setOf("La;")).keys)
    }

    @Test fun `failed updates restore baseline names before judging remaining claims`() {
        val changes = mapOf("update" to AcceptedRename("La;", "Taken"), "new" to AcceptedRename("Lc;", "Original"))
        val conflicts = NameChecks.conflicts(changes, setOf("La;", "Lb;", "Lc;"), mapOf("La;" to "Original", "Lb;" to "Taken"))
        assertEquals(setOf("update", "new"), conflicts.keys)
    }
}
