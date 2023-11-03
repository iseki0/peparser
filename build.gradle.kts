plugins {
    `java-library`
    kotlin("jvm") version "1.9.10"
    application
}

group = "space.iseki.peparser"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("org.jetbrains:annotations:24.0.1")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

