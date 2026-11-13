plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "com.smartvpn.android"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.smartvpn.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
}
