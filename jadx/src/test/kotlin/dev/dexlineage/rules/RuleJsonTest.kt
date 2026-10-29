package dev.dexlineage.rules

import com.google.gson.JsonParser
import dev.dexlineage.io.JsonFiles
import dev.dexlineage.io.ValidationException
import dev.dexlineage.model.Locator
import org.junit.jupiter.api.Test
import kotlin.test.*

class RuleJsonTest {
    private fun parse(text: String) = JsonParser.parseString(text)
    private fun check(text: String) = RuleJson.validateLocator(parse(text))

    @Test fun `a misspelled signature constraint cannot silently become a broader valid rule`() {
        val text = """{"kind":"field-initializer","anchor":"component","factors":[{"kind":"method-signature","returnSameAsField":true,"parameterType":["Ljava/lang/String;"]}]}"""
        // Gson would omit parameterType; the remaining return constraint is independently valid.
        RuleEngine.validate(JsonFiles.gson.fromJson(text, Locator::class.java))
        val error = assertFailsWith<ValidationException> { check(text) }
        assertContains(error.message!!, "parameterType")
    }

    @Test fun `unknown locator and capture fields are rejected before decoding`() {
        assertFailsWith<ValidationException> { check("""{"kind":"string-use","anchor":"x","expectedOwner":"La;"}""") }
        assertFailsWith<ValidationException> { check("""{"kind":"field-initializer","anchor":"x","captures":[{"name":"part","argumentIndex":1,"transform":"className"}]}""") }
    }

    @Test fun `JSON primitive coercions and fractional indexes are rejected`() {
        for (value in listOf("\"1\"", "1.5", "2147483648", "true")) {
            assertFailsWith<ValidationException> {
                check("""{"kind":"field-initializer","anchor":"x","factors":[{"kind":"argument-string","index":$value}]}""")
            }
        }
        assertFailsWith<ValidationException> { check("""{"kind":"field-initializer","anchor":"x","factors":[{"kind":"method-signature","returnSameAsField":"true"}]}""") }
        assertFailsWith<ValidationException> { check("""{"kind":"string-use","anchor":123}""") }
        assertFailsWith<ValidationException> { check("""{"kind":"field-initializer","anchor":"x","factors":[{"kind":"argument-string","index":1,"value":123}]}""") }
    }

    @Test fun `non-null containers and required values cannot be null or missing`() {
        for (fragment in listOf("\"factors\":null", "\"captures\":null", "\"factors\":[null]",
            "\"factors\":[{\"kind\":\"field-flags\",\"requiredFlags\":null}]",
            "\"factors\":[{\"kind\":\"method-signature\",\"returnSameAsField\":null}]",
            "\"factors\":[{\"kind\":\"method-signature\",\"parameterTypes\":[null]}]",
            "\"captures\":[{\"name\":\"x\"}]")) {
            assertFailsWith<ValidationException> { check("""{"kind":"field-initializer","anchor":"x",$fragment}""") }
        }
        assertFailsWith<ValidationException> { check("""{"kind":null,"anchor":"x"}""") }
        assertFailsWith<ValidationException> { check("""{"kind":"string-use"}""") }
    }

    @Test fun `nullable parameters and omitted defaults remain accepted`() {
        check("""{"kind":"field-initializer","anchor":"x","factors":[{"kind":"argument-string","index":1,"value":null,"valueFromCapture":null,"visibility":null,"invocationKind":null,"parameterTypes":null,"returnType":null}]}""")
        check("""{"kind":"string-use","anchor":"x"}""")
        check("""{"kind":"field-initializer","anchor":"x","factors":[{"kind":"argument-string","index":1.0}],"captures":[{"name":"x","argumentIndex":1}]}""")
    }

    @Test fun `templates have their own anchor shape and lists validate every locator`() {
        RuleJson.validateLocator(parse("""{"kind":"field-initializer","anchorFromCapture":"component","factors":[{"kind":"argument-string","index":1,"valueFromCapture":"component"}]}"""), template = true)
        assertFailsWith<ValidationException> { RuleJson.validateLocator(parse("""{"kind":"string-use","anchor":"x"}"""), template = true) }
        assertFailsWith<ValidationException> { check("""{"kind":"string-use","anchorFromCapture":"x"}""") }
        RuleJson.validateLocators(parse("""[{"kind":"string-use","anchor":"x"},{"kind":"string-use","anchor":"y"}]"""))
        assertFailsWith<ValidationException> { RuleJson.validateLocators(parse("""[{"kind":"string-use","anchor":"x"},null]""")) }
        assertFailsWith<ValidationException> { RuleJson.validateLocators(parse("null")) }
    }
}
