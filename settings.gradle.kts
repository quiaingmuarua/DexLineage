pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
rootProject.name = "dexlineage"
include("knowledge", "jadx", "analysis", "migration", "cli")
