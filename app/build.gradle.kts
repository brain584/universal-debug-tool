import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.Alive.Trace"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.Alive.Trace"
        ndkVersion = "30.0.16248370"
        minSdk = 24
        targetSdk = 36
        versionCode = 1200
        versionName = "1.2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    applicationVariants.all {
        outputs.all {
            (this as? com.android.build.gradle.internal.api.BaseVariantOutputImpl)
                ?.outputFileName = "ATrace-$name.apk"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        viewBinding = true
    }

    // 把独立注入器可执行文件打包进 APK assets，
    // 应用解压后可在 `su` 下运行（ptrace 注入需要 root
    // 进程，应用进程本身没有提权）。
    sourceSets {
        getByName("main") {
            assets.srcDir(project.layout.buildDirectory.dir("generated/injectorAssets"))
        }
    }
}

// 用 NDK clang 构建 ptrace 注入器（arm64 可执行文件），
// 输出到 build/generated/injectorAssets/injector（作为 asset 打包）。
val sdkDir: String = Properties().apply {
    rootProject.file("local.properties").inputStream().use { load(it) }
}["sdk.dir"]?.toString() ?: error("sdk.dir not found in local.properties")
val ndkRoot = File(File(sdkDir, "ndk").absolutePath)
    .listFiles()?.maxByOrNull { it.name }
    ?: error("NDK not found under $sdkDir/ndk")
val prebuiltBin = File(ndkRoot, "toolchains/llvm/prebuilt")
    .listFiles()?.first()?.let { File(it, "bin") }
    ?: error("NDK prebuilt toolchain not found")
val isWindows = System.getProperty("os.name").lowercase().contains("windows")
val clangExe = File(
    prebuiltBin,
    "aarch64-linux-android21-clang++" + if (isWindows) ".cmd" else ""
)

tasks.register("buildInjectorExecutable") {
    val srcDir = file("src/main/cpp/injector/src")
    val incDir = file("src/main/cpp/injector/include")
    val outDir = project.layout.buildDirectory.dir("generated/injectorAssets").get().asFile
    val compatDir = project.layout.buildDirectory.dir("generated/injectorCompat").get().asFile
    val compatHeader = File(compatDir, "process_vm_compat.h")
    inputs.dir(srcDir)
    inputs.dir(incDir)
    outputs.dir(outDir)
    outputs.file(compatHeader)
    doLast {
        outDir.mkdirs()
        compatDir.mkdirs()
        // bionic 不把 process_vm_readv/writev 作为 libc 函数导出；
        // 这里以 syscall() 包装提供，使注入器源码
        // 能在任意 NDK 下编译。
        compatHeader.writeText(
            """
            // bionic 的 process_vm 兼容层（syscall 包装）
            #pragma once
            #include <sys/types.h>
            #include <sys/uio.h>
            #include <sys/syscall.h>
            #include <unistd.h>
            #if !defined(__cplusplus)
            #error "process_vm_compat.h requires C++"
            #endif
            static inline ssize_t process_vm_readv(pid_t pid,
                                                   const struct iovec* local_iov,
                                                   unsigned long local_count,
                                                   const struct iovec* remote_iov,
                                                   unsigned long remote_count,
                                                   unsigned long flags) {
                return syscall(SYS_process_vm_readv, pid, local_iov, local_count,
                               remote_iov, remote_count, flags);
            }
            static inline ssize_t process_vm_writev(pid_t pid,
                                                    const struct iovec* local_iov,
                                                    unsigned long local_count,
                                                    const struct iovec* remote_iov,
                                                    unsigned long remote_count,
                                                    unsigned long flags) {
                return syscall(SYS_process_vm_writev, pid, local_iov, local_count,
                               remote_iov, remote_count, flags);
            }
            """.trimIndent()
        )
        // 排除零 ptrace 注入器：它有独立的 main()，由下面的
        // zptArgs 单独编译成 assets/zpt，不能混进 ptrace 注入器一起链接。
        val srcs = fileTree(srcDir) {
            include("*.cpp")
            exclude("zeroptrace_injector.cpp")
        }.files.map { it.absolutePath }
        val commonArgs = listOf(
            "-std=gnu++17", "-D_GNU_SOURCE", "-O2", "-fPIE", "-pie",
            "-static-libstdc++", "-s",
            "-include", compatHeader.absolutePath,
            "-I", incDir.absolutePath,
            "-o", File(outDir, "injector").absolutePath
        ) + srcs + listOf("-llog")
        @Suppress("DEPRECATION")
        project.exec {
            workingDir(projectDir)
            if (isWindows) {
                commandLine("cmd", "/c", clangExe.absolutePath, *commonArgs.toTypedArray())
            } else {
                commandLine(clangExe.absolutePath, *commonArgs.toTypedArray())
            }
        }

        // 零 ptrace 注入器：**单独**编译成 assets/zpt。
        // 它有自己的 main()，不能和上面的 ptrace 注入器源文件一起编译，必须独立一份。
        val zptSrc = File(srcDir, "zeroptrace_injector.cpp")
        if (zptSrc.exists()) {
            val zptArgs = listOf(
                "-std=gnu++17", "-D_GNU_SOURCE", "-O2", "-fPIE", "-pie",
                "-static-libstdc++", "-s",
                "-I", incDir.absolutePath,
                "-o", File(outDir, "zpt").absolutePath,
                zptSrc.absolutePath, "-llog"
            )
            @Suppress("DEPRECATION")
            project.exec {
                workingDir(projectDir)
                if (isWindows) {
                    commandLine("cmd", "/c", clangExe.absolutePath, *zptArgs.toTypedArray())
                } else {
                    commandLine(clangExe.absolutePath, *zptArgs.toTypedArray())
                }
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn("buildInjectorExecutable")
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
