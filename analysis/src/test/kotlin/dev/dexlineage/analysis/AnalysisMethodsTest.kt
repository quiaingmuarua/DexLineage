package dev.dexlineage.analysis

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.dexlineage.io.*
import dev.dexlineage.model.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class AnalysisMethodsTest {
    @TempDir lateinit var temp: Path

    @Test fun `methods reject unknown IDs and unsupported options before execution`() {
        assertFailsWith<ValidationException> { AnalysisMethods.get("unknown") }
        assertFailsWith<ValidationException> { AnalysisMethods.register(listOf(AnalysisMethods.get("profile"), AnalysisMethods.get("profile"))) }
        val generic = AnalysisProfile(id = "sample", discovery = Locator("string-use", "anchor"),
            method = AnalysisMethodSpec("profile", JsonObject().apply { addProperty("hidden", "value") }))
        assertFailsWith<ValidationException> { AnalysisMethods.get("profile").validate(generic) }
        val profile = generic.copy(method = AnalysisMethodSpec("profile"))
        JsonFiles.writeNew(temp.resolve("profile.json"), profile)
        JsonFiles.writeNew(temp.resolve("config.json"), mapOf("schemaVersion" to 4, "apk" to "example.apk", "profile" to "profile.json"))
        val plan = AnalysisMethods.prepareConfig("profile", temp.resolve("config.json"))
        assertTrue(plan.seedSteps.isEmpty())
        assertEquals(profile, plan.profile)
        assertEquals(Digests.artifact(temp.resolve("profile.json")), plan.profileFile)
    }

    @Test fun `messages method owns its finite three seed rounds and never accepts class targets as seeds`() {
        val profile = AnalysisProfile(id = "topic", strategy = StrategySpec("grpc-java.rpc-discovery", requires = mapOf("nameFactory" to "factory")),
            method = AnalysisMethodSpec("messages.grpc", JsonObject().apply { add("reviewServices", JsonFiles.gson.toJsonTree(listOf("example.Group"))) }))
        JsonFiles.writeNew(temp.resolve("profile.json"), profile)
        val rules = AnalysisRuleFile(anchors = listOf(AnalysisAnchorDefinition("seed", locators = listOf(Locator("string-use", "anchor")))))
        JsonFiles.writeNew(temp.resolve("seeds.json"), rules)
        JsonFiles.writeNew(temp.resolve("config.json"), mapOf("schemaVersion" to 4, "apk" to "example.apk", "profile" to "profile.json", "seedRules" to "seeds.json"))
        val plan = AnalysisMethods.prepareConfig("messages.grpc", temp.resolve("config.json"))
        assertEquals(listOf(rules, rules, rules), plan.seedSteps)
        Files.writeString(temp.resolve("seeds.json"), JsonFiles.encode(AnalysisRuleFile(items = listOf(AnalysisRuleItem("rename", locators = listOf(Locator("string-use", "anchor")))))))
        assertFailsWith<ValidationException> { AnalysisMethods.prepareConfig("messages.grpc", temp.resolve("config.json")) }
    }

    @Test fun `legacy RPC profile is decoded only at the boundary and retains exact old encoding`() {
        val old = """{"schemaVersion":4,"id":"legacy","discovery":{"kind":"","anchor":"","factors":[],"captures":[]},"minConfidence":"HIGH","strategy":{"strategyId":"grpc-java.rpc-discovery","parameters":{},"resultKind":"CLASS","requires":{"nameFactory":"factory"}},"parameterCaptures":{},"rpcDrafts":{"reviewServices":["example.Group"],"requestSuffix":"Request","responseSuffix":"Response"}}"""
        val source = JsonParser.parseString(old)
        val profile = JsonFiles.gson.fromJson(source, AnalysisProfile::class.java)
        assertEquals("messages.grpc", AnalysisMethods.forProfile(profile).id)
        assertEquals(source, JsonFiles.gson.toJsonTree(profile))
        assertEquals(JsonFiles.encode(source), JsonFiles.encode(profile))
        val canonical = profile.copy(compatibility = null)
        assertFalse(JsonFiles.encode(canonical).contains("rpcDrafts"))
        assertTrue(JsonFiles.encode(canonical).contains("\"methodId\": \"messages.grpc\""))
        assertEquals(3, AnalysisMethods.forProfile(canonical).seedRounds)
        val bare = source.asJsonObject.deepCopy().also { it.remove("rpcDrafts") }
        val decodedBare = JsonFiles.gson.fromJson(bare, AnalysisProfile::class.java)
        assertEquals("messages.grpc", AnalysisMethods.forProfile(decodedBare).id)
        assertEquals(bare, JsonFiles.gson.toJsonTree(decodedBare))
        assertEquals(JsonFiles.encode(bare), JsonFiles.encode(decodedBare))
    }
}
