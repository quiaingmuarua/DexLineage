package dev.dexlineage.rules

import dev.dexlineage.io.JsonFiles
import dev.dexlineage.io.ValidationException
import dev.dexlineage.model.*
import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.InsnType
import jadx.core.dex.nodes.InsnNode
import org.junit.jupiter.api.Test
import kotlin.test.*

class RuleEngineTest {
    private val owner = ClassRef("a".repeat(64), "Lexample/Owner;", "classes.dex")
    private val conditions = listOf(
        FactorSpec("field-flags", requiredFlags = listOf("STATIC", "FINAL")),
        FactorSpec("invocation-kind", invocationKind = "STATIC"),
        FactorSpec("method-signature", parameterTypes = listOf("Ljava/lang/String;", "Ljava/lang/String;"), returnSameAsField = true),
        FactorSpec("argument-string", index = 0, value = "scope"),
        FactorSpec("argument-string", index = 1),
        FactorSpec("assignment-owner"),
    )
    private val locator = Locator("field-initializer", "scope", conditions, listOf(CaptureSpec("component", 1)))
    private fun binding() = FieldBinding(owner, "log", "Lexample/Logger;", 0x19, "<clinit>()V",
        CallFact("Lexample/Logger;", "factory", listOf("Ljava/lang/String;", "Ljava/lang/String;"), "Lexample/Logger;", "STATIC", listOf("scope", "Component"), 4), owner.descriptor)

    @Test fun `one complete field binding passes and captures actual argument`() {
        val result = RuleEngine.evaluate(binding(), locator)
        assertEquals(MatchStatus.PASS, result.status)
        assertEquals(mapOf("component" to "Component"), result.captures)
        assertEquals(binding(), result.field)
        assertTrue(result.factors.all { it.status == MatchStatus.PASS })
    }

    @Test fun `private static final passes unless profile explicitly requires public`() {
        val privateField = binding().copy(accessFlags = 0x1a)
        assertEquals(MatchStatus.PASS, RuleEngine.evaluate(privateField, locator).status)
        val publicOnly = locator.copy(factors = conditions + FactorSpec("field-flags", visibility = "PUBLIC"))
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(privateField, publicOnly).status)
    }

    @Test fun `cannot join an anchor from one field with flags from another`() {
        val first = binding().copy(fieldName = "first", accessFlags = 1)
        val second = binding().copy(fieldName = "second", call = binding().call!!.copy(arguments = listOf("different-scope", "Component")))
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(first, locator).status)
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(second, locator).status)
    }

    @Test fun `signature mismatches and wrong assignment owner fail`() {
        val wrongSignature = binding().copy(call = binding().call!!.copy(parameterTypes = listOf("Ljava/lang/String;", "I")))
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(wrongSignature, locator).status)
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(binding().copy(assignmentOwner = "Lother/Owner;"), locator).status)
        val wrongReturn = binding().copy(call = binding().call!!.copy(returnType = "Ljava/lang/Object;"))
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(wrongReturn, locator).status)
    }

    @Test fun `unreadable initializer is unknown while known non-invocation fails`() {
        assertEquals(MatchStatus.UNKNOWN, RuleEngine.evaluate(binding().copy(call = null, assignmentOwner = null, unknownReason = "parse failure"), locator).status)
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(binding().copy(call = null), locator).status)
    }

    @Test fun `reader distinguishes a constant initializer from an unsupported expression`() {
        val literalReason = FieldFactsReader.unsupportedInitializerReason(ConstStringNode("scope"))
        assertNull(literalReason)
        val complexReason = FieldFactsReader.unsupportedInitializerReason(InsnNode(InsnType.CHECK_CAST, 1))
        assertNotNull(complexReason)
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(binding().copy(call = null, unknownReason = literalReason), locator).status)
        assertEquals(MatchStatus.UNKNOWN, RuleEngine.evaluate(binding().copy(call = null, unknownReason = complexReason), locator).status)
    }

    @Test fun `a method string cannot supply the anchor missing from a static final logger`() {
        // Raw scanning can nominate this owner because a different method uses "scope".
        // Only the logger initializer arguments are admissible to structural matching.
        val unrelatedLogger = binding().copy(call = binding().call!!.copy(arguments = listOf("other-scope", "Component")))
        val result = RuleEngine.evaluate(unrelatedLogger, locator)
        assertEquals(MatchStatus.FAIL, result.status)
        assertEquals(MatchStatus.FAIL, result.factors.first().status)
    }

    @Test fun `unresolved argument is not a matching string constant`() {
        val missing = binding().copy(call = binding().call!!.copy(arguments = listOf("scope", null)))
        val result = RuleEngine.evaluate(missing, locator)
        assertEquals(MatchStatus.UNKNOWN, result.status)
        assertTrue(result.captures.isEmpty())
        val outOfRange = locator.copy(captures = listOf(CaptureSpec("missing", 2)))
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(binding(), outOfRange).status)
    }

    @Test fun `known non-string arguments fail anchors factors and captures`() {
        val nonString = binding().copy(call = binding().call!!.copy(arguments = listOf("scope", null), knownNonStringArguments = setOf(1)))
        val result = RuleEngine.evaluate(nonString, locator)
        assertEquals(MatchStatus.FAIL, result.status)
        assertEquals(MatchStatus.FAIL, result.factors.single { it.kind == "capture:component" }.status)
        val missingAnchor = nonString.copy(call = nonString.call!!.copy(arguments = listOf(null, null), knownNonStringArguments = setOf(0, 1)))
        assertEquals(MatchStatus.FAIL, RuleEngine.evaluate(missingAnchor, locator).factors.first().status)
    }

    @Test fun `template binds capture not subsequently accepted semantic name`() {
        val template = LocatorTemplate("field-initializer", "component", listOf(
            FactorSpec("field-flags", requiredFlags = listOf("STATIC", "FINAL")),
            FactorSpec("invocation-kind", invocationKind = "STATIC"),
            FactorSpec("method-signature", parameterTypes = listOf("Ljava/lang/String;", "Ljava/lang/String;"), returnSameAsField = true),
            FactorSpec("argument-string", index = 0),
            FactorSpec("argument-string", index = 1, valueFromCapture = "component"),
            FactorSpec("assignment-owner"),
        ), listOf(CaptureSpec("component", 1)))
        val generated = RuleEngine.instantiate(template, mapOf("component" to "Component"))
        val acceptedName = "ComponentV2"
        assertEquals("Component", generated.anchor)
        assertNotEquals(acceptedName, generated.anchor)
        assertEquals("Component", generated.factors.single { it.index == 1 }.value)
        val evolved = binding().copy(call = binding().call!!.copy(declaringType = "Lrenamed/Factory;", methodName = "z", arguments = listOf("new-scope", "Component")))
        assertEquals(MatchStatus.PASS, RuleEngine.evaluate(evolved, generated).status)
    }

    @Test fun `unknown kinds unbound captures and invalid parameters are rejected`() {
        assertFailsWith<ValidationException> { RuleEngine.validate(locator.copy(kind = "magic")) }
        assertFailsWith<ValidationException> { RuleEngine.validate(locator.copy(factors = listOf(FactorSpec("script")))) }
        assertFailsWith<ValidationException> { RuleEngine.validate(locator.copy(factors = listOf(FactorSpec("argument-string", index = 1, valueFromCapture = "unknown")))) }
        assertFailsWith<ValidationException> { RuleEngine.instantiate(LocatorTemplate("string-use", "missing", emptyList()), emptyMap()) }
        assertFailsWith<ValidationException> { RuleEngine.validate(locator.copy(factors = listOf(FactorSpec("field-flags", requiredFlags = listOf("NOT_A_FLAG"))))) }
        assertFailsWith<ValidationException> { RuleEngine.validate(locator.copy(factors = listOf(FactorSpec("assignment-owner", value = "ignored")))) }
        assertFailsWith<ValidationException> { RuleEngine.validate(locator.copy(captures = listOf(CaptureSpec("x", 1), CaptureSpec("x", 0)))) }
    }

    @Test fun `optional JSON defaults retain their declared values`() {
        val json = """{"kind":"field-initializer","anchor":"scope","factors":[{"kind":"invocation-kind","invocationKind":"STATIC"}]}"""
        val parsed = JsonFiles.gson.fromJson(json, Locator::class.java)
        RuleEngine.validate(parsed)
        assertTrue(parsed.captures.isEmpty())
        assertTrue(parsed.factors.single().requiredFlags.isEmpty())
    }

    @Test fun `legacy literal locator remains independent of initializer predicates`() {
        RuleEngine.validate(Locator("string-use", "literal"))
        assertFailsWith<ValidationException> { RuleEngine.validate(Locator("string-use", "literal", listOf(FactorSpec("assignment-owner")))) }
    }

    @Test fun `a known method-only class fails field selection while unreadable metadata stays unknown`() {
        assertEquals(MatchStatus.FAIL, RuleEngine.missingBindings(owner, false, 0).status)
        assertEquals(MatchStatus.UNKNOWN, RuleEngine.missingBindings(owner, true, 0).status)
    }
}
