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

val fixtureProject = rootProject.findProject(":fixture-apk")
val fixtureBuildTiming = layout.buildDirectory.file("fixture-integration/apk-build.json")
var fixtureBuildStartedNanos = 0L

val prepareFixtureApkBuild by tasks.registering {
    group = "verification"
    description = "Check the Android SDK before building the public fixture module."
    doLast {
        check(fixtureProject != null) {
            "Enable the fixture module with -PandroidFixtures=true, then run fixtureIntegrationTest or buildFixtureApks."
        }
        fixtureBuildStartedNanos = System.nanoTime()
        fixtureBuildTiming.get().asFile.apply {
            parentFile.mkdirs()
            writeText("""{"schemaVersion":1,"stage":"apk-build","status":"STARTED"}""")
        }
        val localProperties = rootProject.file("local.properties")
        val localSdk = localProperties.takeIf { it.isFile }?.let { file ->
            Properties().apply { file.inputStream().use(::load) }.getProperty("sdk.dir")?.takeIf { it.isNotBlank() }
        }
        val sdkValue = localSdk
            ?: System.getenv("ANDROID_HOME")?.takeIf { it.isNotBlank() }
            ?: System.getenv("ANDROID_SDK_ROOT")?.takeIf { it.isNotBlank() }
            ?: error("fixtureIntegrationTest requires ANDROID_HOME or sdk.dir in the root local.properties")
        val sdk = rootProject.file(sdkValue)
        check(sdk.resolve("platforms/android-35/android.jar").isFile && sdk.resolve("build-tools/35.0.0").isDirectory) {
            "Install Android SDK platforms;android-35 and build-tools;35.0.0 in $sdk"
        }
    }
}

// Ordering only: building the module directly does not pull in the CLI test lifecycle.
fixtureProject?.tasks?.configureEach { mustRunAfter(prepareFixtureApkBuild) }

val buildFixtureApks by tasks.registering {
    group = "verification"
    description = "Build both R8 APK flavors of the standard fixture-apk Android module."
    dependsOn(prepareFixtureApkBuild)
    if (fixtureProject != null) {
        dependsOn(":fixture-apk:assembleV1Release", ":fixture-apk:assembleV2Release")
    }
    doLast {
        val elapsedMillis = (System.nanoTime() - fixtureBuildStartedNanos) / 1_000_000
        // A failed dependency leaves STARTED and Gradle's task failure diagnostics, never PASS.
        fixtureBuildTiming.get().asFile.writeText(
            """{"schemaVersion":1,"stage":"apk-build","status":"PASS","elapsedMillis":$elapsedMillis}""")
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
