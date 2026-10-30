import java.io.File
import java.util.Properties

plugins {
    kotlin("jvm")
    application
}

dependencies {
    implementation(project(":analysis"))
    implementation(project(":jadx"))
    implementation(project(":migration"))
    runtimeOnly("org.slf4j:slf4j-simple:2.0.13")
    testImplementation(project(":jadx"))
    testImplementation("net.fabricmc:mapping-io:0.6.1")
    testImplementation("io.github.skylot:jadx-core:1.5.0")
    testImplementation("io.github.skylot:jadx-dex-input:1.5.0")
}

application {
    applicationName = "dexlineage"
    mainClass.set("dev.dexlineage.cli.MainKt")
    applicationDefaultJvmArgs = listOf("-Xmx3g", "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn")
}

distributions {
    main {
        contents {
            from(rootProject.file("LICENSE"))
            from(rootProject.file("THIRD_PARTY_NOTICES.md"))
            from(rootProject.file("licenses")) { into("licenses") }
        }
    }
}

// The CLI is the sole owner of the installed distribution; retain the existing root entrypoint.
tasks.named<Sync>("installDist") {
    into(rootProject.layout.buildDirectory.dir("install/dexlineage"))
}

tasks.register<Test>("realCaseTest") {
    description = "Verify prepared, reviewed migration using an explicit local case properties file."
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform { includeTags("real-case") }
    workingDir = rootProject.projectDir
    maxHeapSize = "3g"
    providers.gradleProperty("caseProperties").orNull?.let {
        systemProperty("dexlineage.caseProperties", rootProject.file(it).absolutePath)
    }
    outputs.upToDateWhen { false }
    doFirst {
        check(providers.gradleProperty("caseProperties").isPresent) {
            "Pass -PcaseProperties=<local .properties file>; normal test/build never require private APKs."
        }
    }
}

val buildFixtureApks by tasks.registering(Exec::class) {
    group = "verification"
    description = "Build the independently configured Android fixture project with this repository's Wrapper."
    workingDir(rootProject.projectDir)
    isIgnoreExitValue = true
    var startedNanos = 0L
    val timingReport = layout.buildDirectory.file("fixture-integration/apk-build.json")
    doFirst {
        startedNanos = System.nanoTime()
        timingReport.get().asFile.apply {
            parentFile.mkdirs()
            writeText("""{"schemaVersion":1,"stage":"apk-build","status":"STARTED"}""")
        }
        val localSdk = listOf("local.properties", "fixtures/android/local.properties")
            .map { rootProject.file(it) }.filter { it.isFile }.firstNotNullOfOrNull { file ->
                Properties().apply { file.inputStream().use(::load) }.getProperty("sdk.dir")?.takeIf { it.isNotBlank() }
            }
        val sdkValue = System.getenv("ANDROID_HOME")?.takeIf { it.isNotBlank() }
            ?: System.getenv("ANDROID_SDK_ROOT")?.takeIf { it.isNotBlank() }
            ?: localSdk
            ?: error("fixtureIntegrationTest requires ANDROID_HOME or sdk.dir in local.properties")
        val sdk = rootProject.file(sdkValue)
        check(sdk.resolve("platforms/android-35/android.jar").isFile && sdk.resolve("build-tools/35.0.0").isDirectory) {
            "Install Android SDK platforms;android-35 and build-tools;35.0.0 in $sdk"
        }
        environment("ANDROID_HOME", sdk.absolutePath)
        environment("ANDROID_SDK_ROOT", sdk.absolutePath)
        val javaName = if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java"
        // Same committed wrapper entrypoint as gradlew, without shell quoting differences.
        commandLine(File(System.getProperty("java.home"), "bin/$javaName").absolutePath,
            "-classpath", rootProject.file("gradle/wrapper/gradle-wrapper.jar").absolutePath,
            "org.gradle.wrapper.GradleWrapperMain", "-p", rootProject.file("fixtures/android").absolutePath,
            ":app:assembleV1Release", ":app:assembleV2Release", "--no-daemon", "--console=plain")
    }
    doLast {
        val exitCode = executionResult.get().exitValue
        val elapsedMillis = (System.nanoTime() - startedNanos) / 1_000_000
        val status = if (exitCode == 0) "PASS" else "FAIL"
        timingReport.get().asFile.writeText(
            """{"schemaVersion":1,"stage":"apk-build","status":"$status","exitCode":$exitCode,"elapsedMillis":$elapsedMillis}""")
        check(exitCode == 0) { "Fixture APK build failed (exit $exitCode); see ${timingReport.get().asFile}" }
    }
}

tasks.register<Test>("fixtureIntegrationTest") {
    description = "Run real CLI integration against the public R8-built fixture APKs."
    group = "verification"
    dependsOn(buildFixtureApks, tasks.named("installDist"))
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform { includeTags("fixture-integration") }
    workingDir = rootProject.projectDir
    maxHeapSize = "1g"
    maxParallelForks = 1
    systemProperty("dexlineage.fixtureRoot", rootProject.file("fixtures/android").absolutePath)
    systemProperty("dexlineage.fixtureCases", rootProject.file("fixtures/cases.json").absolutePath)
    systemProperty("dexlineage.distributionDir", rootProject.layout.buildDirectory.dir("install/dexlineage").get().asFile.absolutePath)
    systemProperty("dexlineage.fixtureResults", layout.buildDirectory.dir("fixture-integration").get().asFile.absolutePath)
    outputs.upToDateWhen { false }
}
