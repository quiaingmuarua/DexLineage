package dev.dexlineage.rules

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import dev.dexlineage.io.*

/** Reject misspelled constraints and Gson coercions before decoding the supported rule DTOs. */
object RuleJson {
    fun validateLocators(json: JsonElement): Unit = checkedInput("locator list") {
        array(json, "locators").forEach { validateLocator(it) }
    }

    fun validateLocator(json: JsonElement, template: Boolean = false): Unit = checkedInput("rule JSON") {
        val context = if (template) "locatorTemplate" else "locator"
        val obj = objectValue(json, context)
        val anchorKey = if (template) "anchorFromCapture" else "anchor"
        fields(obj, setOf("kind", anchorKey, "factors", "captures"), context)
        string(required(obj, "kind", context), "$context.kind")
        string(required(obj, anchorKey, context), "$context.$anchorKey")
        obj["factors"]?.let { factors -> array(factors, "$context.factors").forEachIndexed { i, value ->
            factor(value, "$context.factors[$i]")
        } }
        obj["captures"]?.let { captures -> array(captures, "$context.captures").forEachIndexed { i, value ->
            val at = "$context.captures[$i]"
            val capture = objectValue(value, at)
            fields(capture, setOf("name", "argumentIndex"), at)
            string(required(capture, "name", at), "$at.name")
            integer(required(capture, "argumentIndex", at), "$at.argumentIndex")
        } }
        Unit
    }

    private fun factor(json: JsonElement, context: String) {
        val obj = objectValue(json, context)
        fields(obj, setOf("kind", "requiredFlags", "visibility", "invocationKind", "parameterTypes",
            "returnType", "returnSameAsField", "index", "value", "valueFromCapture"), context)
        string(required(obj, "kind", context), "$context.kind")
        obj["requiredFlags"]?.let { strings(it, "$context.requiredFlags") }
        for (key in listOf("visibility", "invocationKind", "returnType", "value", "valueFromCapture")) {
            obj[key]?.takeUnless { it.isJsonNull }?.let { string(it, "$context.$key") }
        }
        obj["parameterTypes"]?.takeUnless { it.isJsonNull }?.let { strings(it, "$context.parameterTypes") }
        obj["returnSameAsField"]?.let {
            requireInput(it.isJsonPrimitive && it.asJsonPrimitive.isBoolean, "Expected JSON boolean: $context.returnSameAsField")
        }
        obj["index"]?.takeUnless { it.isJsonNull }?.let { integer(it, "$context.index") }
    }

    private fun objectValue(value: JsonElement, context: String): JsonObject {
        requireInput(value.isJsonObject, "Expected JSON object: $context")
        return value.asJsonObject
    }

    private fun fields(obj: JsonObject, allowed: Set<String>, context: String) {
        val unknown = obj.keySet() - allowed
        requireInput(unknown.isEmpty(), "Unsupported fields in $context: ${unknown.sorted().joinToString()}")
    }

    private fun required(obj: JsonObject, key: String, context: String): JsonElement =
        obj[key] ?: throw ValidationException("Missing $context.$key")

    private fun string(value: JsonElement, context: String) {
        requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isString, "Expected JSON string: $context")
    }

    private fun integer(value: JsonElement, context: String) {
        requireInput(value.isJsonPrimitive && value.asJsonPrimitive.isNumber, "Expected JSON integer: $context")
        try { value.asBigDecimal.intValueExact() }
        catch (e: ArithmeticException) { throw ValidationException("Expected exact 32-bit integer: $context", e) }
        catch (e: NumberFormatException) { throw ValidationException("Invalid JSON integer: $context", e) }
    }

    private fun array(value: JsonElement, context: String): List<JsonElement> {
        requireInput(value.isJsonArray, "Expected JSON array: $context")
        return value.asJsonArray.toList()
    }

    private fun strings(value: JsonElement, context: String) {
        array(value, context).forEachIndexed { i, item -> string(item, "$context[$i]") }
    }
}
