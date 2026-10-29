package dev.dexlineage.cli

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class CliTest {
    @Test fun `help and version work without private files`() {
        assertEquals(0, runCli(arrayOf("--help")))
        assertEquals(0, runCli(arrayOf("--version")))
    }
    @Test fun `invalid options have validation exit code`() {
        assertEquals(2, runCli(arrayOf("unknown")))
        assertEquals(2, runCli(arrayOf("prepare", "--case")))
        assertEquals(2, runCli(arrayOf("bootstrap", "discover")))
        assertEquals(2, runCli(arrayOf("analysis", "inspect", "--run", "r", "--task", "a", "--task", "b")))
        assertEquals(2, runCli(arrayOf("migration", "tasks", "--run", "r", "--limit", "bad")))
    }
}
