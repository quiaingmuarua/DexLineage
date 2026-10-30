package dev.dexlineage.cli.fixtures

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class R8OracleTest {
    @TempDir lateinit var temporary: Path

    @Test fun `full member oracle maps overload parameter return and array element types`() {
        val mapping = temporary.resolve("mapping.txt")
        Files.writeString(mapping, """
            fixture.Owner -> a:
                fixture.Value field -> b
                fixture.Value[][] values -> c
                fixture.Value factory(fixture.Value[],java.lang.String,int) -> d
                int factory(int) -> d
                void <init>() -> <init>
            fixture.Value -> e:
        """.trimIndent())
        val oracle = R8Oracle(mapping)

        assertEquals(RawDexFieldRef("La;", "b", "Le;"), oracle.field("fixture.Owner", "field", "Lfixture/Value;"))
        assertEquals(RawDexFieldRef("La;", "c", "[[Le;"), oracle.field("fixture.Owner", "values", "[[Lfixture/Value;"))
        assertEquals(RawDexMethodRef("La;", "d", listOf("[Le;", "Ljava/lang/String;", "I"), "Le;"),
            oracle.method("fixture.Owner", "factory", "([Lfixture/Value;Ljava/lang/String;I)Lfixture/Value;"))
        assertEquals("(I)I", oracle.method("fixture.Owner", "factory", "(I)I").descriptor)
        assertEquals("()V", oracle.method("fixture.Owner", "<init>", "()V").descriptor)
        assertFailsWith<IllegalStateException> { oracle.method("fixture.Owner", "factory", "(J)I") }
        assertFailsWith<IllegalStateException> { oracle.field("fixture.Owner", "field", "I") }
    }
}
