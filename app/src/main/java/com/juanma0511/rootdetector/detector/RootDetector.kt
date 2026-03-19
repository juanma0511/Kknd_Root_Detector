package com.juanma0511.rootdetector.detector

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity
import java.io.File

class RootDetector(private val context: Context) {

    private val suPaths = listOf(
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/system/bin/su64", "/system/xbin/su64", "/system_ext/bin/su",
        "/system_ext/xbin/su", "/product/bin/su", "/vendor/bin/su",
        "/vendor/xbin/su", "/system/bin/.ext/.su", "/system/xbin/daemonsu",
        "/system/usr/we-need-root/su-backup", "/su/bin/su", "/debug_ramdisk/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/cache/recovery/su",
        "/data/adb/su", "/data/local/tmp/su", "/system/app/Superuser.apk",
        "/system/etc/init.d/99SuperSUDaemon", "/system/xbin/sugote"
    )

    private val rootPackages = listOf(
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "eu.chainfire.supersu", "eu.chainfire.supersu.pro",
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su", "com.kingouser.com",
        "com.kingroot.kinguser", "com.kingo.root",
        "com.smedialink.oneclickroot", "com.alephzain.framaroot",
        "com.jrummy.root.browserfree", "com.jrummy.roots.browserfree",
        "com.topjohnwu.magisk", "io.github.topjohnwu.magisk",
        "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
        "io.github.vvb2060.magisk.delta", "io.github.a13e300.magisk",
        "io.github.1q23lyc45.magisk", "com.topjohnwu.magisk.alpha",
        "me.weishu.kernelsu", "com.rifsxd.ksunext",
        "com.sukisu.ultra", "io.github.a13e300.ksuwebui",
        "me.bmax.apatch", "me.yuki.folk",
        "org.lsposed.manager", "org.lsposed.lspatch",
        "io.github.lsposed.manager", "com.lsposed.manager",
        "de.robv.android.xposed.installer", "me.weishu.exp",
        "com.solohsu.android.edxp.manager", "org.meowcat.edxposed.manager",
        "com.fox2code.mmm", "com.fox2code.mmm.debug", "com.fox2code.mmm.fdroid",
        "com.dergoogler.mmrl", "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus", "com.chrisbjohnson.hiddenroot",
        "stericson.busybox", "stericson.busybox.donate",
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.android.vending.billing.InAppBillingService.LUCK"
    )

    private val patchedApps = listOf(
        "app.revanced.android.youtube", "app.revanced.android.youtube.music",
        "com.mgoogle.android.gms", "app.revanced.manager.flutter", "app.revanced.manager",
        "app.rvx.android.youtube", "app.rvx.android.youtube.music",
        "com.coderstory.toolkit", "com.catsoft.hmafree",
        "com.catsoft.hma", "me.hsc.hma", "app.hma.free",
        "app.hma", "com.tsng.hidemyapplist", "org.frknkrc44.hma_oss",
        "org.lsposed.manager", "org.lsposed.lspatch", "io.github.lsposed.manager",
        "com.lsposed.manager", "de.robv.android.xposed.installer",
        "com.solohsu.android.edxp.manager", "org.meowcat.edxposed.manager",
        "me.weishu.exp",
        "com.speedsoftware.rootexplorer", "com.estrongs.android.pop",
        "com.fox2code.mmm", "com.dergoogler.mmrl"
    )

    private val warningApps = linkedMapOf(
        "moe.shizuku.privileged.api" to "Shizuku",
        "com.termux" to "Termux",
        "com.termux.api" to "Termux:API",
        "bin.mt.plus" to "MT Manager",
        "com.draco.ladb" to "LADB",
        "io.github.muntashirakon.AppManager" to "App Manager",
        "io.github.muntashirakon.AppManager.debug" to "App Manager Debug"
    )

    private val oplusExPrefixes = listOf(
        "com.oplus.ex",
        "com.coloros.ex",
        "com.heytap.ex",
        "com.oneplus.ex",
        "com.realme.ex"
    )

    private val magiskPaths = listOf(
        "/sbin/.magisk", "/sbin/.core/mirror", "/sbin/.core/img",
        "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magisk.db",
        "/data/adb/modules", "/data/adb/modules_update", "/data/adb/service.d",
        "/data/adb/post-fs-data.d", "/data/adb/overlay", "/data/adb/ksu",
        "/data/adb/ksud", "/data/adb/ksu/bin", "/data/adb/ap",
        "/data/adb/apd", "/data/adb/ap/bin", "/debug_ramdisk/.magisk",
        "/cache/.disable_magisk", "/system/addon.d/99-magisk.sh",
        "/dev/.magisk.unblock", "/dev/magisk_merge", "/dev/ksud", "/dev/ksu", "/dev/apatch"
    )

    private val dangerousBinaries = listOf("su", "busybox", "magisk", "magisk64", "magiskpolicy", "resetprop", "supolicy", "ksud", "ksuinit", "apd")
    private val binaryPaths = listOf(
        "/sbin/", "/system/bin/", "/system/xbin/", "/system_ext/bin/",
        "/system_ext/xbin/", "/product/bin/", "/vendor/bin/", "/vendor/xbin/",
        "/data/local/xbin/", "/data/local/bin/", "/data/local/tmp/", "/su/bin/",
        "/debug_ramdisk/", "/data/adb/ksu/bin/"
    )

    fun runAllChecks(progressCallback: (Int) -> Unit = {}): List<DetectionItem> {
        val checks: List<() -> List<DetectionItem>> = listOf(
            ::checkSuBinaries,
            ::checkRootPackages,
            ::checkPatchedApps,
            ::checkWarningApps,
            ::checkBuildTags,
            ::checkDangerousProps,
            ::checkRootBinaries,
            ::checkWritablePaths,
            ::checkMagiskFiles,
            ::checkFrida,
            ::checkEmulator,
            ::checkMountPoints,
            ::checkTestKeys,
            ::checkNativeLibMaps,
            ::checkMagiskTmpfs,
            ::checkKernelSU,
            ::checkZygiskModules,
            ::checkSuInPath,
            ::checkSELinux,
            ::checkPackageManagerAnomalies,
            ::checkCustomRom,
            ::checkKernelCmdline,
            ::checkEnvHooks,
            ::checkDevSockets,
            ::checkZygoteInjection,
            ::checkOverlayFS,
            ::checkZygoteFDLeak,
            ::checkProcessCapabilities,
            ::checkSpoofedProps,
            ::checkSuspiciousMountSources,
            ::checkMountInfoConsistency,
            ::checkBinderServices,
            ::checkProcessEnvironment,
            ::checkMemfdArtifacts,
            ::checkPropertyConsistency,
            ::checkHideBypassModules,
            ::checkHiddenMagiskModules
        )
        val items = mutableListOf<DetectionItem>()
        val total = checks.size + 1 
        items.add(ZygiskDetector().detect())
        items.add(OverlayFsDetector().detect())
        items.add(MountNamespaceDetector().detect())
        
        checks.forEachIndexed { i, check ->
            items += check()
            progressCallback(((i + 1) * 100) / total)
        }

        val native = NativeChecks()
        items += native.run()

        val integrity = IntegrityChecker(context)
        items += integrity.runAllChecks()

        progressCallback(100)
        return items
    }

    private fun checkSuBinaries(): List<DetectionItem> {
        val found = suPaths.filter { File(it).exists() }
        return listOf(det(
            "su_binary", "SU Binary Paths", DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Checks for su binary in 17 known root paths",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkRootPackages(): List<DetectionItem> {
        val pm = context.packageManager
        val found = linkedSetOf<String>()
        rootPackages.forEach { pkg ->
            when {
                isPackageInstalled(pm, pkg) -> found += pkg
                pm.getLaunchIntentForPackage(pkg) != null -> found += "$pkg (launchable)"
            }
        }
        val filteredFound = found.filterNot(::isOplusExPackage)
        return listOf(det(
            "root_apps", "Root Manager Apps", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Magisk, KernelSU, APatch, SuperSU, LSPosed and 50+ known packages",
            filteredFound.isNotEmpty(), filteredFound.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkPatchedApps(): List<DetectionItem> {
        val pm = context.packageManager
        val found = linkedSetOf<String>()
        patchedApps.forEach { pkg ->
            when {
                isPackageInstalled(pm, pkg) -> found += pkg
                pm.getLaunchIntentForPackage(pkg) != null -> found += "$pkg (launchable)"
            }
        }
        val filteredFound = found.filterNot(::isOplusExPackage)
        return listOf(det(
            "patched_apps", "Patched / Modified Apps", DetectionCategory.ROOT_APPS, Severity.MEDIUM,
            "ReVanced, CorePatch, Play Integrity Fix, TrickyStore, HMA, LSPosed and companion tools",
            filteredFound.isNotEmpty(), filteredFound.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkWarningApps(): List<DetectionItem> {
        val pm = context.packageManager
        val found = linkedSetOf<String>()
        warningApps.forEach { (pkg, label) ->
            when {
                isPackageInstalled(pm, pkg) -> found += "$label ($pkg)"
                pm.getLaunchIntentForPackage(pkg) != null -> found += "$label ($pkg launchable)"
            }
        }
        try {
            @Suppress("DEPRECATION")
            val installedPackages = pm.getInstalledPackages(PackageManager.GET_META_DATA or PackageManager.MATCH_UNINSTALLED_PACKAGES)
            installedPackages
                .map { it.packageName }
                .filter(::isOplusExPackage)
                .sorted()
                .forEach { found += "OplusEx utility ($it)" }
        } catch (_: Exception) {}
        return listOf(det(
            "warning_apps", "Non-Rooted Power Apps", DetectionCategory.ROOT_APPS, Severity.LOW,
            "Shizuku, Termux, MT Manager, LADB, OplusEx utilities and similar tools are not root by themselves, but they are useful for debugging, shell access and vendor maintenance",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkBuildTags(): List<DetectionItem> {
        val tags = Build.TAGS ?: ""
        return listOf(det(
            "build_tags", "Build Tags (test-keys)", DetectionCategory.BUILD_TAGS, Severity.MEDIUM,
            "Release builds must use release-keys, not test-keys",
            tags.contains("test-keys"), "Build.TAGS=$tags"
        ))
    }

    private fun checkDangerousProps(): List<DetectionItem> {
        val found = GetPropCatalog.collectMatches(::getProp, GetPropCatalog.dangerousRootProps)
        return listOf(det(
            "dangerous_props", "Dangerous System Props", DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "Debuggable builds, unlocked verified boot, adb root and persistent root props",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkRootBinaries(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        dangerousBinaries.forEach { bin ->
            binaryPaths.forEach { path ->
                val file = File("$path$bin")
                if (file.exists() || file.canExecute()) {
                    found += file.absolutePath
                }
            }
        }
        return listOf(det(
            "root_binaries", "Root Binaries", DetectionCategory.BUSYBOX, Severity.HIGH,
            "Searches for su, busybox, magisk, resetprop, KernelSU and APatch binaries in extended paths",
            found.isNotEmpty(), found.take(10).joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkWritablePaths(): List<DetectionItem> {
        val writable = linkedSetOf<String>()
        val protectedPaths = listOf("/system", "/system_root", "/system_ext", "/vendor", "/product", "/odm")
        protectedPaths.forEach { path ->
            if (runCatching { File(path).canWrite() }.getOrDefault(false)) {
                writable += "$path (filesystem write access)"
            }
        }
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 4) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                val options = parts[3]
                if (protectedPaths.any { mountPoint == it || mountPoint.startsWith("$it/") }) {
                    val optionList = options.split(",")
                    if (optionList.any { it == "rw" } || fileSystem == "overlay" || device.contains("tmpfs") || device.contains("overlay")) {
                        writable += "$mountPoint [$device $fileSystem $options]"
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "rw_paths", "Writable System Paths", DetectionCategory.WRITABLE_PATHS, Severity.HIGH,
            "System, vendor and product partitions should not be writable or overlaid on stock builds",
            writable.isNotEmpty(), writable.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMagiskFiles(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        magiskPaths.forEach { path ->
            if (File(path).exists()) {
                found += path
            }
        }
        return listOf(det(
            "magisk_files", "Magisk / KSU / APatch Files", DetectionCategory.MAGISK, Severity.HIGH,
            "Checks Magisk, KernelSU and APatch artifacts under /data/adb, /dev and ramdisk mirrors",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkFrida(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        listOf("frida-server", "frida-helper", "frida-agent", "gum-js-loop").forEach { name ->
            if (isProcessRunning(name)) {
                evidence += "process=$name"
            }
        }
        listOf(27042, 27043, 27049, 23946).forEach { port ->
            val open = try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 150)
                socket.close()
                true
            } catch (_: Exception) {
                false
            }
            if (open) {
                evidence += "port=$port"
            }
        }
        try {
            File("/proc/self/maps").forEachLine { line ->
                val lower = line.lowercase()
                if (lower.contains("frida-agent") || lower.contains("frida-gadget")) {
                    evidence += line.trim().take(120)
                }
            }
        } catch (_: Exception) {}
        evidence += collectNetUnixMatches(listOf("frida")).take(3)
        return listOf(det(
            "frida", "Frida Instrumentation", DetectionCategory.FRIDA, Severity.HIGH,
            "Looks for Frida processes, loopback ports, unix sockets and injected maps entries",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkEmulator(): List<DetectionItem> {
        val indicators = mutableListOf<String>()
        val fp = Build.FINGERPRINT ?: ""
        
        if (fp.startsWith("generic") || fp.contains(":generic/")) indicators += "FINGERPRINT starts with generic"
        if (Build.HARDWARE == "goldfish" || Build.HARDWARE == "ranchu") indicators += "HARDWARE=${Build.HARDWARE}"
        if (Build.MANUFACTURER.equals("Genymotion", ignoreCase = true)) indicators += "MANUFACTURER=Genymotion"
        val emuProducts = setOf("sdk_gphone_x86", "sdk_gphone64_x86_64", "sdk_x86", "google_sdk", "vbox86p", "generic_x86")
        if (Build.PRODUCT in emuProducts) indicators += "PRODUCT=${Build.PRODUCT}"
        return listOf(det(
            "emulator", "Emulator / Virtual Device", DetectionCategory.EMULATOR, Severity.MEDIUM,
            "Exact emulator hardware/product/fingerprint signatures",
            indicators.isNotEmpty(), indicators.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMountPoints(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val targets = listOf("/system", "/system_root", "/system_ext", "/vendor", "/product", "/odm")
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 4) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                val options = parts[3]
                val protectedMount = targets.any { mountPoint == it || mountPoint.startsWith("$it/") }
                val writable = options.split(",").any { it == "rw" }
                val suspiciousSource = device.startsWith("/dev/block/") || device.startsWith("dm-") || device.contains("overlay") || device.contains("tmpfs")
                if (protectedMount && (writable || fileSystem == "overlay" || suspiciousSource && (device.contains("overlay") || device.contains("tmpfs")))) {
                    suspicious += "$mountPoint [$device $fileSystem $options]"
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "mount_rw", "RW System Mount Points", DetectionCategory.MOUNT_POINTS, Severity.HIGH,
            "/proc/mounts shows writable, overlaid or tmpfs-backed system partitions",
            suspicious.isNotEmpty(), suspicious.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkTestKeys(): List<DetectionItem> {
        val fp = Build.FINGERPRINT ?: ""
        val detected = fp.contains("test-keys") || fp.contains("dev-keys")
        return listOf(det(
            "test_keys", "Test/Dev Keys in Fingerprint", DetectionCategory.BUILD_TAGS, Severity.MEDIUM,
            "Build.FINGERPRINT should not contain test-keys or dev-keys",
            detected, if (detected) fp else null
        ))
    }

    private fun checkNativeLibMaps(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        val systemPaths = listOf("/system/", "/apex/", "/vendor/", "/product/", "/odm/")
        val keywords = frameworkKeywords()
        try {
            File("/proc/self/maps").forEachLine { line ->
                val lower = line.lowercase()
                val matches = keywords.filter { lower.contains(it) }
                if (matches.isNotEmpty() && systemPaths.none { line.contains(it) }) {
                    found += "${matches.joinToString(",")} -> ${line.trim().take(120)}"
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "native_lib_maps", "Injected Native Libraries", DetectionCategory.MAGISK, Severity.HIGH,
            "/proc/self/maps contains root-framework libraries outside trusted system paths",
            found.isNotEmpty(), found.take(6).joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMagiskTmpfs(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        if (File("/dev/magisk").exists()) evidence += "/dev/magisk exists"
        if (File("/sbin/.magisk").exists()) evidence += "/sbin/.magisk exists"
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 3) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                if (fileSystem == "tmpfs" && mountPoint == "/sbin") evidence += "tmpfs on /sbin"
                if (mountPoint == "/debug_ramdisk") evidence += "/debug_ramdisk present"
                if (line.contains(".magisk") || line.contains("/data/adb") || line.contains("overlay")) {
                    if (mountPoint.startsWith("/system") || mountPoint.startsWith("/vendor") || mountPoint.startsWith("/product") || mountPoint.startsWith("/odm") || mountPoint == "/debug_ramdisk") {
                        evidence += "$mountPoint [$device $fileSystem]"
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "magisk_tmpfs", "Magisk tmpfs / debug_ramdisk", DetectionCategory.MAGISK, Severity.HIGH,
            "Looks for Magisk ramdisk mirrors, tmpfs staging points and overlay-backed mounts",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkKernelSU(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        GetPropCatalog.kernelSuProps.forEach { prop ->
            val value = getProp(prop)
            if (value.isNotEmpty()) {
                evidence += "prop $prop=$value"
            }
        }
        listOf("me.weishu.kernelsu", "com.rifsxd.ksunext", "com.sukisu.ultra", "io.github.a13e300.ksuwebui").forEach { pkg ->
            if (isPackageInstalled(context.packageManager, pkg)) {
                evidence += "package $pkg"
            }
        }
        listOf("/dev/ksud", "/dev/ksu", "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu/bin", "/sys/module/kernelsu", "/sys/kernel/ksu", "/proc/kernelsu").forEach { path ->
            if (File(path).exists()) {
                evidence += path
            }
        }
        evidence += collectNetUnixMatches(listOf("ksu", "kernelsu", "ksunext")).take(4)
        try {
            val initMaps = File("/proc/1/maps")
            if (initMaps.exists()) {
                initMaps.forEachLine { line ->
                    val lower = line.lowercase()
                    if (lower.contains("ksu") || lower.contains("kernelsu") || lower.contains("susfs")) {
                        evidence += line.trim().take(120)
                    }
                }
            }
        } catch (_: Exception) {}
        try {
            val output = Runtime.getRuntime().exec("getprop").inputStream.bufferedReader().readText()
            if (output.contains("kernelsu", true) || output.contains("ksunext", true) || output.contains("susfs", true)) {
                evidence += "getprop output leaks KernelSU markers"
            }
        } catch (_: Exception) {}
        return listOf(det(
            "kernelsu", "KernelSU / KSU Next", DetectionCategory.MAGISK, Severity.HIGH,
            "Checks KernelSU props, sockets, proc nodes, maps and manager packages",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkZygiskModules(): List<DetectionItem> {
        val moduleDirs = listOf("/data/adb/modules", "/data/adb/modules_update", "/data/adb/riru/modules")
        val knownDangerous = mapOf(
            "playintegrityfix" to "Play Integrity Fix",
            "pif" to "Play Integrity Fix",
            "tricky_store" to "TrickyStore",
            "trickystore" to "TrickyStore",
            "hidemyapplist" to "Hide My Applist",
            "hma" to "Hide My Applist",
            "lsposed" to "LSPosed",
            "zygisk_lsposed" to "LSPosed (Zygisk)",
            "riru_lsposed" to "LSPosed (Riru)",
            "shamiko" to "Shamiko",
            "zygisk-assistant" to "Zygisk Assistant",
            "zygisksu" to "ZygiskSU",
            "susfs" to "SUSFS",
            "ksu_susfs" to "KernelSU SUSFS",
            "safetynet-fix" to "SafetyNet Fix",
            "magiskhidepropsconf" to "MagiskHide Props Config",
            "magical_overlayfs" to "Magical OverlayFS",
            "riru" to "Riru",
            "denylist" to "DenyList helper"
        )
        val detectedModules = linkedSetOf<String>()
        val genericModules = linkedSetOf<String>()
        val scanFiles = listOf("module.prop", "service.sh", "post-fs-data.sh", "customize.sh", "sepolicy.rule")
        moduleDirs.forEach { dirPath ->
            File(dirPath).takeIf { it.isDirectory }?.listFiles()?.forEach { module ->
                val moduleName = module.name.lowercase()
                val textMatches = mutableSetOf<String>()
                scanFiles.forEach { fileName ->
                    val file = File(module, fileName)
                    if (file.exists()) {
                        val content = runCatching { file.readText().lowercase() }.getOrNull().orEmpty()
                        knownDangerous.keys.filter { content.contains(it) }.forEach { textMatches += it }
                    }
                }
                val nameMatch = knownDangerous.keys.firstOrNull { moduleName.contains(it) }
                val contentMatch = textMatches.firstOrNull()
                when {
                    nameMatch != null -> detectedModules += "${module.name} -> ${knownDangerous.getValue(nameMatch)}"
                    contentMatch != null -> detectedModules += "${module.name} -> ${knownDangerous.getValue(contentMatch)}"
                    else -> genericModules += module.name
                }
            }
        }
        val allFound = detectedModules + genericModules
        val detail = buildString {
            if (detectedModules.isNotEmpty()) {
                append("Known dangerous:\n")
                detectedModules.forEach { appendLine(it) }
            }
            if (genericModules.isNotEmpty()) {
                append("Other modules:\n")
                genericModules.take(8).forEach { appendLine(it) }
            }
        }.trim()
        return listOf(det(
            "zygisk_modules", "Magisk / KSU Modules Installed",
            DetectionCategory.MAGISK, Severity.HIGH,
            "Scans active and pending module directories plus module scripts for hiding and spoofing frameworks",
            allFound.isNotEmpty(), detail.ifEmpty { null }
        ))
    }

    private fun checkSuInPath(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        val pathValue = System.getenv("PATH").orEmpty()
        pathValue.split(":").filter { it.isNotBlank() }.forEach { dir ->
            val file = File("$dir/su")
            if (file.exists()) {
                found += file.absolutePath
            }
            if (dir.contains("/su") || dir.contains("/data/adb") || dir.contains("/data/local")) {
                found += "PATH:$dir"
            }
        }
        return listOf(det(
            "su_in_path", "SU in \$PATH", DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Walks PATH for su binaries and root-specific executable directories",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSELinux(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val permissive = try {
            val process = Runtime.getRuntime().exec("getenforce")
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result.equals("Permissive", ignoreCase = true)
        } catch (_: Exception) {
            false
        }
        if (permissive) {
            evidence += "getenforce=Permissive"
        }
        val enforceFile = try {
            File("/sys/fs/selinux/enforce").readText().trim() == "0"
        } catch (_: Exception) {
            false
        }
        if (enforceFile) {
            evidence += "/sys/fs/selinux/enforce=0"
        }
        val bootSelinux = getProp("ro.boot.selinux")
        if (bootSelinux.equals("permissive", ignoreCase = true)) {
            evidence += "ro.boot.selinux=$bootSelinux"
        }
        return listOf(det(
            "selinux", "SELinux Permissive", DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "Permissive SELinux is a strong indicator of tampering and often survives root hiding",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkPackageManagerAnomalies(): List<DetectionItem> {
        val anomalies = linkedSetOf<String>()
        val pm = context.packageManager
        try {
            @Suppress("DEPRECATION")
            val installedPackages = pm.getInstalledPackages(PackageManager.GET_META_DATA or PackageManager.MATCH_UNINSTALLED_PACKAGES)
            val packageNames = installedPackages.map { it.packageName }.toSet()
            (rootPackages + patchedApps).forEach { pkg ->
                if (pkg in packageNames) {
                    anomalies += pkg
                }
                if (pm.getLaunchIntentForPackage(pkg) != null) {
                    anomalies += "$pkg (launch intent)"
                }
            }
        } catch (_: Exception) {}
        listOf(
            "com.topjohnwu.magisk.MAIN",
            "org.lsposed.manager.LAUNCH_MANAGER",
            "com.rifsxd.ksunext.MAIN",
            "me.weishu.kernelsu.action.MAIN"
        ).forEach { action ->
            try {
                val resolved = pm.queryIntentActivities(Intent(action), PackageManager.MATCH_DEFAULT_ONLY)
                if (resolved.isNotEmpty()) {
                    resolved.mapNotNull { it.activityInfo?.packageName }.forEach { anomalies += "$action -> $it" }
                }
            } catch (_: Exception) {}
        }
        val filteredAnomalies = anomalies.filterNot { entry ->
            val packageName = entry.substringBefore(" ").substringAfterLast("-> ")
            isOplusExPackage(packageName)
        }
        return listOf(det(
            "pm_anomalies", "Package Manager Check", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Scans installed packages, launch intents and known manager actions for hidden root apps",
            filteredAnomalies.isNotEmpty(), filteredAnomalies.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun frameworkKeywords(): List<String> = DetectorTrust.frameworkKeywords()

    private fun isOplusExPackage(packageName: String): Boolean =
        oplusExPrefixes.any { packageName.startsWith(it, ignoreCase = true) }

    private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
        val flagSets = listOf(
            PackageManager.GET_META_DATA,
            PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.GET_META_DATA,
            0
        )
        return flagSets.any { flags ->
            try {
                pm.getPackageInfo(packageName, flags)
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun collectNetUnixMatches(keywords: List<String>): List<String> {
        val matches = linkedSetOf<String>()
        try {
            File("/proc/net/unix").forEachLine { line ->
                val lower = line.lowercase()
                if (keywords.any { lower.contains(it) }) {
                    matches += line.trim().takeLast(120)
                }
            }
        } catch (_: Exception) {}
        return matches.toList()
    }

    private fun findZygotePid(): String? = try {
        File("/proc").listFiles()?.firstOrNull { entry ->
            val pid = entry.name.toIntOrNull() ?: return@firstOrNull false
            val cmdline = File("/proc/$pid/cmdline")
            cmdline.exists() && cmdline.readText().contains("zygote")
        }?.name
    } catch (_: Exception) {
        null
    }

    private fun readStatusValue(field: String): String? = try {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith(field) }?.substringAfter(":")?.trim()
        }
    } catch (_: Exception) {
        null
    }

    private fun bootLooksLockedAndNormal(): Boolean = DetectorTrust.bootLooksTrustedLocked()

    private fun strongRootMountSignal(signature: String, mountPoint: String, trustedLocked: Boolean): Boolean =
        DetectorTrust.hasRootMountSignal(signature, mountPoint, trustedLocked)

    private fun isSuspiciousDeletedOrMemfdMap(line: String, trustedLocked: Boolean): Boolean =
        DetectorTrust.isSuspiciousDeletedOrMemfdMap(line, trustedLocked)

    private fun det(
        id: String, name: String, cat: DetectionCategory, sev: Severity,
        desc: String, detected: Boolean, detail: String?
    ) = DetectionItem(id=id, name=name, description=desc, category=cat, severity=sev,
                      detected=detected, detail=detail)

    private fun getProp(key: String): String = try {
        val p = Runtime.getRuntime().exec("getprop $key")
        val finished = p.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)
        if (!finished) { p.destroyForcibly(); "" }
        else p.inputStream.bufferedReader().readLine()?.trim() ?: ""
    } catch (_: Exception) { "" }

    private fun isProcessRunning(name: String): Boolean = try {
        Runtime.getRuntime().exec("ps -A").inputStream
            .bufferedReader().lineSequence().any { it.contains(name) }
    } catch (_: Exception) { false }

        private fun checkKernelCmdline(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        try {
            val cmdline = File("/proc/cmdline").readText()
            val flags = listOf(
                "androidboot.selinux=permissive",
                "androidboot.verifiedbootstate=orange",
                "androidboot.verifiedbootstate=yellow",
                "androidboot.flash.locked=0",
                "androidboot.vbmeta.device_state=unlocked",
                "androidboot.veritymode=disabled",
                "androidboot.veritymode=logging",
                "skip_initramfs",
                "init=/system/bin/sh",
                "selinux=0",
                "enforcing=0"
            )
            flags.forEach { flag ->
                if (cmdline.contains(flag)) {
                    suspicious += flag
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "kernel_cmdline",
            "Kernel Boot Parameters",
            DetectionCategory.SYSTEM_PROPS,
            Severity.HIGH,
            "Checks /proc/cmdline for insecure boot flags, unlocked AVB and permissive SELinux",
            suspicious.isNotEmpty(),
            suspicious.joinToString("\n").ifEmpty { null }
        ))
    }

        private fun checkEnvHooks(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        try {
            val env = mapOf(
                "LD_PRELOAD" to System.getenv("LD_PRELOAD"),
                "LD_LIBRARY_PATH" to System.getenv("LD_LIBRARY_PATH"),
                "DYLD_INSERT_LIBRARIES" to System.getenv("DYLD_INSERT_LIBRARIES"),
                "CLASSPATH" to System.getenv("CLASSPATH")
            )
            env.forEach { (key, value) ->
                val current = value.orEmpty()
                val lower = current.lowercase()
                if (current.isNotEmpty() && (frameworkKeywords().any { lower.contains(it) } || lower.contains("/data/") || lower.contains("/tmp/") || lower.contains("/debug_ramdisk"))) {
                    suspicious += "$key=$current"
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "env_hooks",
            "Environment Hooking",
            DetectionCategory.MAGISK,
            Severity.MEDIUM,
            "Suspicious preload, linker and classpath values leaking root frameworks or injected files",
            suspicious.isNotEmpty(),
            suspicious.joinToString("\n").ifEmpty { null }
        ))
    }

        private fun checkDevSockets(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        val keywords = listOf("magisk", "zygisk", "ksu", "kernelsu", "lsposed", "apatch", "riru")
        try {
            File("/dev/socket").listFiles()?.forEach { file ->
                val name = file.name.lowercase()
                if (keywords.any { name.contains(it) }) {
                    found += file.absolutePath
                }
            }
        } catch (_: Exception) {}
        found += collectNetUnixMatches(keywords).take(6)
        return listOf(det(
            "dev_sockets",
            "Suspicious Dev Sockets",
            DetectionCategory.MAGISK,
            Severity.HIGH,
            "Scans /dev/socket and /proc/net/unix for Magisk, KernelSU, APatch and LSPosed sockets",
            found.isNotEmpty(),
            found.joinToString("\n").ifEmpty { null }
        ))
    }

        private fun checkZygoteInjection(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        try {
            val zygotePid = findZygotePid()
            if (zygotePid != null) {
                File("/proc/$zygotePid/maps").forEachLine { line ->
                    val lower = line.lowercase()
                    val matches = frameworkKeywords().filter { lower.contains(it) }
                    if (matches.isNotEmpty()) {
                        suspicious += "${matches.joinToString(",")} -> ${line.trim().take(120)}"
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "zygote_injection",
                "Zygote Injection",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Checks zygote memory maps for Zygisk, LSPosed, Riru, KernelSU and APatch artifacts",
                suspicious.isNotEmpty(),
                suspicious.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkOverlayFS(): List<DetectionItem> {
        val overlays = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 4) return@forEachLine
                val mountPoint = parts[1]
                if (
                    mountPoint.startsWith("/system") ||
                    mountPoint.startsWith("/system_ext") ||
                    mountPoint.startsWith("/vendor") ||
                    mountPoint.startsWith("/product") ||
                    mountPoint.startsWith("/odm")
                ) {
                    if (strongRootMountSignal(line, mountPoint, trustedLocked)) {
                        overlays += line.take(160)
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "overlayfs",
                "OverlayFS System Modification",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Detects overlay-backed system mounts, Magisk magic mount traces and /data/adb-backed overlays",
                overlays.isNotEmpty(),
                overlays.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkZygoteFDLeak(): List<DetectionItem> {
        val leaks = linkedSetOf<String>()
        try {
            val zygotePid = findZygotePid() ?: return emptyList()
            File("/proc/$zygotePid/fd").listFiles()?.forEach { entry ->
                val target = runCatching { entry.canonicalPath.lowercase() }.getOrDefault("")
                if (frameworkKeywords().any { target.contains(it) }) {
                    leaks += target
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "zygote_fd",
                "Zygote FD Leak",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Detects file descriptor leaks from Zygisk, LSPosed, Riru, KernelSU and APatch into zygote",
                leaks.isNotEmpty(),
                leaks.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkProcessCapabilities(): List<DetectionItem> {
        val elevated = linkedSetOf<String>()
        listOf("CapEff", "CapPrm", "CapBnd").forEach { field ->
            val value = readStatusValue(field)
            if (!value.isNullOrEmpty() && value != "0000000000000000") {
                elevated += "$field=$value"
            }
        }
        return listOf(
            det(
                "process_caps",
                "Linux Capabilities",
                DetectionCategory.SYSTEM_PROPS,
                Severity.HIGH,
                "Process has non-zero effective, permitted or bounding Linux capabilities",
                elevated.isNotEmpty(),
                elevated.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkSpoofedProps(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        suspicious += GetPropCatalog.collectMatches(::getProp, GetPropCatalog.spoofedBootProps)
        return listOf(
            det(
                "boot_state",
                "Bootloader / VerifiedBoot State",
                DetectionCategory.SYSTEM_PROPS,
                Severity.HIGH,
                "Detects unlocked or tampered AVB, dm-verity and warranty state props",
                suspicious.isNotEmpty(),
                suspicious.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkSuspiciousMountSources(): List<DetectionItem> {
        val mounts = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 3) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                val protectedMount = mountPoint.startsWith("/system") || mountPoint.startsWith("/system_ext") || mountPoint.startsWith("/vendor") || mountPoint.startsWith("/product") || mountPoint.startsWith("/odm")
                if (protectedMount && strongRootMountSignal("$device [$fileSystem]", mountPoint, trustedLocked)) {
                    mounts += "$device -> $mountPoint [$fileSystem]"
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "suspicious_mount",
                "Suspicious System Mount Source",
                DetectionCategory.MOUNT_POINTS,
                Severity.HIGH,
                "System partitions should not be backed by overlay, tmpfs or loop devices",
                mounts.isNotEmpty(),
                mounts.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkBinderServices(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        try {
            val process = Runtime.getRuntime().exec("service list")
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()
            frameworkKeywords().filter { output.contains(it, true) }.forEach { suspicious += it }
        } catch (_: Exception) {}
        return listOf(
            det(
                "binder_services",
                "Suspicious Binder Services",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Binder services registered by Magisk, LSPosed, Riru, KernelSU or APatch components",
                suspicious.isNotEmpty(),
                suspicious.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkProcessEnvironment(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        try {
            System.getenv().forEach { (key, value) ->
                val lower = "$key=$value".lowercase()
                if (frameworkKeywords().any { lower.contains(it) } || lower.contains("/data/adb") || lower.contains("/debug_ramdisk")) {
                    suspicious += "$key=$value"
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "env_scan",
                "Environment Variable Scan",
                DetectionCategory.MAGISK,
                Severity.MEDIUM,
                "Environment variables leaking root frameworks, adb staging paths or hidden overlays",
                suspicious.isNotEmpty(),
                suspicious.joinToString("\n").ifEmpty { null }
            )
        )
    }

        private fun checkHiddenMagiskModules(): List<DetectionItem> {
        val detected = linkedSetOf<String>()
        val keywords = listOf("lsposed", "zygisk", "shamiko", "riru", "playintegrityfix", "trickystore", "susfs", "kernelsu", "apatch")
        val scanFiles = listOf("module.prop", "service.sh", "post-fs-data.sh", "customize.sh", "sepolicy.rule")
        try {
            listOf("/data/adb/modules", "/data/adb/modules_update").forEach { dirPath ->
                File(dirPath).listFiles()?.forEach { module ->
                    val moduleName = module.name.lowercase()
                    if (keywords.any { moduleName.contains(it) }) {
                        detected += module.name
                        return@forEach
                    }
                    val hit = scanFiles.any { fileName ->
                        val file = File(module, fileName)
                        file.exists() && runCatching { file.readText().lowercase() }.getOrDefault("").let { content ->
                            keywords.any { content.contains(it) }
                        }
                    }
                    if (hit) {
                        detected += module.name
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "hidden_modules",
                "Hidden Magisk Modules",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Detects hidden or pending Magisk modules through names and module scripts",
                detected.isNotEmpty(),
                detected.joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkMountInfoConsistency(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()

        fun readMountInfo(path: String): Map<String, String> {
            val result = linkedMapOf<String, String>()
            try {
                File(path).forEachLine { line ->
                    val parts = line.split(" ")
                    val sep = parts.indexOf("-")
                    if (parts.size < 10 || sep == -1) return@forEachLine
                    val mountPoint = parts[4]
                    val fileSystem = parts.getOrNull(sep + 1).orEmpty()
                    val source = parts.getOrNull(sep + 2).orEmpty()
                    if (
                        mountPoint.startsWith("/system") ||
                        mountPoint.startsWith("/system_ext") ||
                        mountPoint.startsWith("/vendor") ||
                        mountPoint.startsWith("/product") ||
                        mountPoint.startsWith("/odm") ||
                        mountPoint.startsWith("/debug_ramdisk") ||
                        mountPoint.startsWith("/.magisk") ||
                        mountPoint.startsWith("/data/adb")
                    ) {
                        result[mountPoint] = "$source [$fileSystem]"
                    }
                }
            } catch (_: Exception) {}
            return result
        }

        val trustedLocked = bootLooksLockedAndNormal()
        val selfMounts = readMountInfo("/proc/self/mountinfo")
        val initMounts = readMountInfo("/proc/1/mountinfo")
        selfMounts.forEach { (mountPoint, selfSignature) ->
            val initSignature = initMounts[mountPoint]
            if (initSignature == null) {
                if (strongRootMountSignal(selfSignature, mountPoint, trustedLocked)) {
                    suspicious += "$mountPoint self-only=$selfSignature"
                }
            } else if (initSignature != selfSignature) {
                val combined = "$selfSignature :: $initSignature"
                if (strongRootMountSignal(combined, mountPoint, trustedLocked)) {
                    suspicious += "$mountPoint self=$selfSignature init=$initSignature"
                }
            }
        }

        return listOf(
            det(
                "mountinfo_consistency",
                "MountInfo Consistency",
                DetectionCategory.MOUNT_POINTS,
                Severity.HIGH,
                "Only flags mount namespace differences when root-specific overlays, adb mounts or Magisk-like traces are present",
                suspicious.isNotEmpty(),
                suspicious.take(8).joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkMemfdArtifacts(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        var anonymousRwx = 0
        try {
            File("/proc/self/maps").forEachLine { line ->
                val lower = line.lowercase()
                val ignoredAnon = lower.contains("[stack") || lower.contains("[anon:dalvik") || lower.contains("[anon:art") || lower.contains("[anon:scudo")
                if ((line.contains("rwxp") || line.contains("r-xs")) && !ignoredAnon && frameworkKeywords().any { lower.contains(it) }) {
                    anonymousRwx++
                }
                if (isSuspiciousDeletedOrMemfdMap(line, trustedLocked)) {
                    suspicious += line.trim().take(140)
                }
            }
        } catch (_: Exception) {}
        if (anonymousRwx > 4) {
            suspicious += "framework_rwx_pages=$anonymousRwx"
        }
        return listOf(
            det(
                "memfd_injection",
                "Memfd / Deleted Injection Maps",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Only flags deleted or memfd mappings when they are tied to hook frameworks or executable injected payloads",
                suspicious.isNotEmpty(),
                suspicious.take(8).joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkPropertyConsistency(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val debuggable = getProp("ro.debuggable").lowercase()
        val secure = getProp("ro.secure").lowercase()
        val buildType = getProp("ro.build.type").lowercase()
        val buildTags = getProp("ro.build.tags").lowercase()
        val vbmetaState = getProp("ro.boot.vbmeta.device_state").lowercase()
        val verifiedBoot = getProp("ro.boot.verifiedbootstate").lowercase()
        val flashLocked = getProp("ro.boot.flash.locked").lowercase()

        if (debuggable == "1" && secure == "1") {
            suspicious += "ro.debuggable=1 with ro.secure=1"
        }
        if (buildTags.contains("release-keys") && (buildType == "userdebug" || buildType == "eng")) {
            suspicious += "release-keys with ro.build.type=$buildType"
        }
        if (verifiedBoot == "green" && vbmetaState == "unlocked") {
            suspicious += "green verified boot with vbmeta unlocked"
        }
        if (flashLocked == "1" && (vbmetaState == "unlocked" || verifiedBoot == "orange" || verifiedBoot == "yellow")) {
            suspicious += "flash locked but boot state says unlocked"
        }
        if ((verifiedBoot == "orange" || verifiedBoot == "yellow") && (flashLocked == "1" || vbmetaState == "locked")) {
            suspicious += "verified boot is $verifiedBoot while lock state looks locked"
        }

        return listOf(
            det(
                "prop_consistency",
                "Property Consistency",
                DetectionCategory.SYSTEM_PROPS,
                Severity.HIGH,
                "Flags inconsistent verified boot, build and security props often produced by resetprop spoofing",
                suspicious.isNotEmpty(),
                suspicious.joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkHideBypassModules(): List<DetectionItem> {
        val detected = linkedSetOf<String>()
        val keywords = listOf(
            "shamiko", "trickystore", "playintegrityfix", "integrityfix", "safetynetfix",
            "safetynet-fix", "hidemyapplist", "hide my applist", "denylist", "deny-list",
            "susfs", "nohello", "zygisk assistant", "zygiskassistant"
        )
        val scanFiles = listOf("module.prop", "service.sh", "post-fs-data.sh", "customize.sh", "action.sh", "system.prop", "sepolicy.rule")
        val moduleDirs = listOf("/data/adb/modules", "/data/adb/modules_update", "/metadata/adb/modules", "/mnt/.magisk/modules")

        try {
            moduleDirs.forEach { dirPath ->
                File(dirPath).listFiles()?.forEach { module ->
                    val name = module.name.lowercase()
                    val normalizedName = name.replace(Regex("[^a-z0-9]"), "")
                    val nameHit = keywords.any { key ->
                        val normalizedKey = key.replace(Regex("[^a-z0-9]"), "")
                        name.contains(key) || normalizedName.contains(normalizedKey)
                    }
                    if (nameHit) {
                        detected += "${module.name} @ $dirPath"
                        return@forEach
                    }
                    val fileHit = scanFiles.any { fileName ->
                        val file = File(module, fileName)
                        file.exists() && runCatching { file.readText().lowercase() }.getOrDefault("").let { content ->
                            keywords.any { key -> content.contains(key) }
                        }
                    }
                    if (fileHit) {
                        detected += "${module.name} @ $dirPath"
                    }
                }
            }
        } catch (_: Exception) {}

        return listOf(
            det(
                "hide_bypass_modules",
                "Hide / Integrity Bypass Modules",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Finds hiding and integrity bypass modules such as Shamiko, TrickyStore, PlayIntegrityFix, HideMyAppList and SUSFS",
                detected.isNotEmpty(),
                detected.take(8).joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkCustomRom(): List<DetectionItem> {
        val indicators = mutableListOf<String>()

        val romProps = mapOf(
            "ro.lineage.version"          to "LineageOS",
            "ro.lineage.build.version"    to "LineageOS",
            "ro.cm.version"               to "CyanogenMod",
            "ro.crdroid.version"          to "crDroid",
            "ro.evolution.version"        to "EvolutionX",
            "ro.arrow.version"            to "ArrowOS",
            "ro.havoc.version"            to "HavocOS",
            "ro.pe.version"               to "PixelExperience",
            "ro.pa.version"               to "ParanoidAndroid",
            "ro.derp.version"             to "DerpFest",
            "ro.elixir.version"           to "ProjectElixir",
            "ro.potato.version"           to "POSP",
            "ro.superior.version"         to "SuperiorOS",
            "ro.spark.version"            to "SparkOS",
            "ro.bliss.version"            to "BlissROMs",
            "ro.phhgsi.android.version"   to "PHH-GSI"
        )

        romProps.forEach { (prop, rom) ->
            val v = getProp(prop)
            if (v.isNotEmpty()) indicators += "$rom ($v)"
        }

        val fp = android.os.Build.FINGERPRINT ?: ""
        val brand = android.os.Build.BRAND ?: ""
        if (fp.contains("lineage", ignoreCase = true)) indicators += "LineageOS in fingerprint"
        if (fp.contains("evolution", ignoreCase = true)) indicators += "EvolutionX in fingerprint"
        if (brand.equals("LineageOS", ignoreCase = true)) indicators += "Brand=LineageOS"

        listOf("/system/etc/lineage-release", "/system/lineage").forEach { path ->
            if (java.io.File(path).exists()) indicators += path
        }

        return listOf(det(
            "custom_rom", "Custom / Third-Party ROM", DetectionCategory.CUSTOM_ROM, Severity.MEDIUM,
            "LineageOS, crDroid, EvolutionX, PixelExperience, ArrowOS and 10+ custom ROMs",
            indicators.isNotEmpty(), indicators.joinToString("\n").ifEmpty { null }
        ))
    }
}
