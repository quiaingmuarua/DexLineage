plugins { id("com.android.application") }

android {
    namespace = "dev.dexlineage.fixture"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    defaultConfig {
        applicationId = "dev.dexlineage.fixture"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "fixture"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        buildConfig = false
        resValues = false
    }
    flavorDimensions += "fixtureVersion"
    productFlavors {
        create("v1") {
            dimension = "fixtureVersion"
            applicationIdSuffix = ".v1"
            proguardFile("v1-rules.pro")
        }
        create("v2") {
            dimension = "fixtureVersion"
            applicationIdSuffix = ".v2"
            versionCode = 2
            proguardFile("v2-rules.pro")
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            // No signing configuration: these APKs are statically analyzed, never installed.
            proguardFiles("fixture-rules.pro")
        }
    }
}
