pluginManagement { repositories { google(); gradlePluginPortal(); mavenCentral() } }
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.10.0"
}
rootProject.name = "dexlineage"
include("knowledge", "jadx", "analysis", "migration", "cli")

// Android Studio imports the APK module with the same settings and Wrapper.
// CLI-only builds do not configure AGP or require an Android SDK.
val fixtureTaskRequested = gradle.startParameter.taskNames.any {
    it.substringAfterLast(':') in setOf("fixtureIntegrationTest", "buildFixtureApks") ||
        it.trimStart(':').startsWith("fixture-apk:")
}
val ideImport = providers.systemProperty("idea.active").orNull == "true" ||
    providers.gradleProperty("android.injected.invoked.from.ide").orNull == "true"
val androidFixtures = providers.gradleProperty("androidFixtures")
    .map { it.toBooleanStrict() }.getOrElse(ideImport || fixtureTaskRequested)
check(androidFixtures || !fixtureTaskRequested) {
    "Android fixture tasks require -PandroidFixtures=true; remove -PandroidFixtures=false."
}
if (androidFixtures) {
    include(":fixture-apk")
    project(":fixture-apk").projectDir = file("fixtures/android")
}
