plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

dependencies {
    implementation("com.github.singbox-android:libbox:1.14.4")
}

android {
    namespace = "com.smartvpn.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.smartvpn.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 13
        versionName = "0.6.6"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}
