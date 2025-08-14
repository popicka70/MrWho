plugins {
    kotlin("jvm") version "1.9.24"
    id("io.ktor.plugin") version "2.3.12"
    application
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("io.ktor.server.netty.EngineMain")
}

repositories {
    mavenCentral()
}

val ktorVersion = "2.3.12"
val logbackVersion = "1.4.14"
val jacksonVersion = "2.17.2"

dependencies {
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-netty-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:$ktorVersion")
    implementation("io.ktor:ktor-serialization-jackson-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-sessions-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-auth-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-java-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-content-negotiation-jvm:$ktorVersion")
    // Use ContentNegotiation + Jackson; older client-jackson is not needed in Ktor 3
    // implementation("io.ktor:ktor-client-jackson:$ktorVersion")

    // Explicit Jackson dependencies to resolve com.fasterxml imports and Kotlin module support
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jacksonVersion")

    // Needed by jackson-module-kotlin for reflection metadata
    implementation(kotlin("reflect"))
    implementation("ch.qos.logback:logback-classic:$logbackVersion")
    testImplementation(kotlin("test"))
}

ktor {
    fatJar {
        archiveFileName.set("MrWhoDemoKtor-all.jar")
    }
}
