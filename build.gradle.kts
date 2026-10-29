import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    base
    kotlin("jvm") version "2.2.10" apply false
}

allprojects {
    group = "dev.dexlineage"
    version = "0.3.0"
    repositories { mavenCentral(); google() }
}

subprojects {
    dependencyLocking { lockAllConfigurations() }
    pluginManager.withPlugin("org.jetbrains.kotlin.jvm") {
        extensions.configure<KotlinJvmProjectExtension> { jvmToolchain(21) }
        dependencies {
            add("testImplementation", "org.jetbrains.kotlin:kotlin-test-junit5:2.2.10")
            add("testImplementation", "org.junit.jupiter:junit-jupiter:5.11.4")
            add("testRuntimeOnly", "org.junit.platform:junit-platform-launcher:1.11.4")
        }
        tasks.withType<Test>().configureEach { useJUnitPlatform() }
        tasks.named<Test>("test") { useJUnitPlatform { excludeTags("real-case", "fixture-integration") } }
    }
}

val modules = listOf("knowledge", "jadx", "analysis", "migration", "cli")
tasks.register("test") {
    group = "verification"
    description = "Run public-data-only tests in all modules."
    dependsOn(modules.map { ":$it:test" })
}
tasks.named("check") { dependsOn(modules.map { ":$it:check" }) }
tasks.named("assemble") { dependsOn(modules.map { ":$it:assemble" }) }
tasks.named("build") { dependsOn(modules.map { ":$it:build" }) }
tasks.named("clean") { dependsOn(modules.map { ":$it:clean" }) }
tasks.register("installDist") {
    group = "distribution"
    description = "Install the CLI distribution at build/install/dexlineage."
    dependsOn(":cli:installDist")
}
tasks.register("realCaseTest") {
    group = "verification"
    description = "Run the explicitly configured real-case integration test in cli."
    dependsOn(":cli:realCaseTest")
}

tasks.register("fixtureIntegrationTest") {
    group = "verification"
    description = "Build public R8 APK fixtures and exercise the installed CLI end to end."
    dependsOn(":cli:fixtureIntegrationTest")
}
