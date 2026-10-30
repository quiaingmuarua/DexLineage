package dev.dexlineage.analysis

import com.google.gson.*
import com.google.gson.reflect.TypeToken
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import dev.dexlineage.io.requireInput

/** Read-only schema-4 compatibility. Old bytes/IDs retain their original field layout. */
class AnalysisCompatibilityCodec : TypeAdapterFactory {
    override fun <T : Any?> create(gson: Gson, type: TypeToken<T>): TypeAdapter<T>? {
        if (type.rawType !in setOf(AnalysisProfile::class.java, AnalysisDiscovery::class.java, AnalysisRun::class.java)) return null
        val delegate = gson.getDelegateAdapter(this, type)
        val tree = gson.getAdapter(JsonElement::class.java)
        return object : TypeAdapter<T>() {
            override fun read(reader: JsonReader): T {
                val json = tree.read(reader).asJsonObject
                requireInput(!(json.has("rpcCalls") && json.get("methodArtifacts")?.isJsonNull == false), "Cannot combine legacy and current method artifacts")
                requireInput(!(json.has("rpcDrafts") && json.get("method")?.isJsonNull == false), "Cannot combine legacy and current method settings")
                val legacy = JsonObject()
                val copy = json.deepCopy()
                if (type.rawType == AnalysisProfile::class.java && json.has("rpcDrafts")) {
                    legacy.add("rpcDrafts", copy.remove("rpcDrafts"))
                    copy.add("method", JsonObject().apply {
                        addProperty("methodId", "messages.grpc")
                        add("parameters", legacy.get("rpcDrafts").deepCopy())
                    })
                }
                if (type.rawType == AnalysisProfile::class.java && !json.has("method") && !json.has("rpcDrafts") &&
                    json.getAsJsonObject("strategy")?.get("strategyId")?.asString == "grpc-java.rpc-discovery") {
                    legacy.addProperty("implicitMethod", true)
                    copy.add("method", JsonObject().apply { addProperty("methodId", "messages.grpc"); add("parameters", JsonObject()) })
                }
                if (json.has("rpcCalls")) legacy.add("rpcCalls", copy.remove("rpcCalls"))
                val result = delegate.fromJsonTree(copy)
                @Suppress("UNCHECKED_CAST")
                return if (legacy.size() == 0) result else when (result) {
                    is AnalysisProfile -> result.copy(compatibility = legacy)
                    is AnalysisDiscovery -> result.copy(compatibility = legacy)
                    is AnalysisRun -> result.copy(compatibility = legacy)
                    else -> result
                } as T
            }

            override fun write(writer: JsonWriter, value: T) {
                val json = delegate.toJsonTree(value).asJsonObject
                val legacy = when (value) {
                    is AnalysisProfile -> value.compatibility
                    is AnalysisDiscovery -> value.compatibility
                    is AnalysisRun -> value.compatibility
                    else -> null
                }
                if (legacy == null) { tree.write(writer, json); return }
                if (legacy.has("implicitMethod")) json.remove("method")
                if (legacy.has("rpcDrafts")) { json.remove("method"); json.add("rpcDrafts", legacy.get("rpcDrafts").deepCopy()) }
                if (legacy.has("rpcCalls")) {
                    // Old discovery places rpcCalls before unresolvedPaths; old run places it last.
                    val restored = JsonObject()
                    json.entrySet().forEach { (key, entry) ->
                        if (key == "unresolvedPaths") restored.add("rpcCalls", legacy.get("rpcCalls").deepCopy())
                        restored.add(key, entry)
                    }
                    if (!restored.has("rpcCalls")) restored.add("rpcCalls", legacy.get("rpcCalls").deepCopy())
                    tree.write(writer, restored)
                } else tree.write(writer, json)
            }
        }
    }
}

/** Only this boundary recognizes the old profile fields; current profiles use method parameters. */
internal object AnalysisProfileWire {
    fun validateFields(json: JsonObject) {
        requireInput(json.keySet().all { it in setOf("schemaVersion", "id", "discovery", "nameCapture", "locatorTemplate", "minConfidence", "strategy", "strategyTemplate", "parameterCaptures", "method", "rpcDrafts") }, "Unknown discovery profile field")
        requireInput(!(json.has("method") && json.has("rpcDrafts")), "Do not combine method and legacy profile settings")
        json.get("method")?.takeUnless { it.isJsonNull }?.asJsonObject?.let {
            requireInput(it.keySet().all { key -> key in setOf("methodId", "parameters") }, "Unknown Analysis method setting")
        }
    }
}
