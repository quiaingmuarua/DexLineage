plugins {
    kotlin("jvm")
    `java-library`
}

dependencies {
    api(project(":knowledge"))
    implementation("io.github.skylot:jadx-core:1.5.0")
    implementation("io.github.skylot:jadx-dex-input:1.5.0")
    implementation("io.github.skylot:jadx-rename-mappings:1.5.0")
    implementation("net.fabricmc:mapping-io:0.6.1")
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.13")
}
