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

    private val suPaths = HardcodedSignals.suPaths
    private val rootPackages = HardcodedSignals.rootPackages
    private val patchedApps = HardcodedSignals.patchedApps
    private val warningApps = LinkedHashMap(HardcodedSignals.warningApps)
    private val magiskPaths = HardcodedSignals.magiskPaths
    private val dangerousBinaries = HardcodedSignals.dangerousBinaries
    private val binaryPaths = HardcodedSignals.binaryPaths
    private val protectedSystemPaths = HardcodedSignals.protectedSystemPaths
    private val fridaProcesses = HardcodedSignals.fridaProcesses
    private val fridaPorts = HardcodedSignals.fridaPorts
    private val emulatorProducts = HardcodedSignals.emuProducts.toSet()
    private val kernelSuPackages = HardcodedSignals.kernelSuPackages
    private val kernelSuPaths = HardcodedSignals.kernelSuPaths
    private val moduleDirs = HardcodedSignals.moduleDirs
    private val moduleScanFiles = HardcodedSignals.moduleScanFiles
    private val managerActions = HardcodedSignals.managerActions
    private val envKeys = HardcodedSignals.envKeys
    private val devSocketKeywords = HardcodedSignals.devSocketKeywords
    private val kernelCmdlineFlags = HardcodedSignals.kernelCmdlineFlags
    private val hiddenModuleKeywords = HardcodedSignals.hiddenModuleKeywords
    private val hideBypassKeywords = HardcodedSignals.hideBypassKeywords
    private val customRomProps = HardcodedSignals.customRomProps
    private val customRomKeywords = HardcodedSignals.customRomKeywords
    private val customRomFiles = HardcodedSignals.customRomFiles
    private val lineageServices = HardcodedSignals.lineageServices
    private val lineagePermissions = HardcodedSignals.lineagePermissions
    private val lineageInitFiles = HardcodedSignals.lineageInitFiles
    private val lineageSepolicyFiles = HardcodedSignals.lineageSepolicyFiles
    private val knownDangerousModules = HardcodedSignals.knownDangerousModules
    private val frameworkSweepKeywords = HardcodedSignals.allFrameworkSweepKeywords

    fun runAllChecks(progressCallback: (Int) -> Unit = {}): List<DetectionItem> {
        val checks: List<() -> List<DetectionItem>> = listOf(
            ::checkSuBinaries,
            ::checkRootPackages,
            ::checkPatchedApps,
            ::checkWarningApps,
            ::checkOplusPackages,
            ::checkBuildTags,
            ::checkDangerousProps,
            ::checkRootBinaries,
            ::checkWritablePaths,
            ::checkMagiskFiles,
            ::checkOplusDirectories,
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
            ::checkLineageServices,
            ::checkLineagePermissions,
            ::checkLineageInitFiles,
            ::checkLineageSepolicy,
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
    
            ::checkMemfdArtifacts,
            ::checkPropertyConsistency,
            ::checkHideBypassModules,
            ::checkHiddenMagiskModules,
            ::checkHardcodedFrameworkSweep,
            ::checkTmpfsOnData,
            ::checkSuTimestamps,
            ::checkApkInstallSource
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
        val (regularFound, _) = splitOplusMatches(found)
        return listOf(det(
            "su_binary", "SU Binary Paths", DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Checks for su binary in 17 known root paths",
            regularFound.isNotEmpty(), regularFound.joinToString("\n").ifEmpty { null }
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
        val (regularFound, _) = splitOplusMatches(found)
        return listOf(det(
            "root_apps", "Root Manager Apps", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Magisk, KernelSU, APatch, SuperSU, LSPosed and 50+ known packages",
            regularFound.isNotEmpty(), regularFound.joinToString("\n").ifEmpty { null }
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
        val (regularFound, _) = splitOplusMatches(found)
        return listOf(det(
            "patched_apps", "Patched / Modified Apps", DetectionCategory.ROOT_APPS, Severity.MEDIUM,
            "ReVanced, CorePatch, Play Integrity Fix, TrickyStore, HMA, LSPosed and companion tools",
            regularFound.isNotEmpty(), regularFound.joinToString("\n").ifEmpty { null }
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
        return listOf(det(
            "warning_apps", "Non-Rooted Power Apps", DetectionCategory.ROOT_APPS, Severity.LOW,
            "Shizuku, Termux, MT Manager, LADB and similar tools are not root by themselves, but they are useful for debugging, shell access and package editing",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkOplusPackages(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        val pm = context.packageManager
        try {
            @Suppress("DEPRECATION")
            val installedPackages = pm.getInstalledPackages(PackageManager.GET_META_DATA or PackageManager.MATCH_UNINSTALLED_PACKAGES)
            installedPackages.forEach { info ->
                val packageName = info.packageName
                if (isOplusMarker(packageName) && pm.getLaunchIntentForPackage(packageName) != null) {
                    found += "$packageName (launchable)"
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "oplus_apps", "Oplus / OplusEx Apps", DetectionCategory.ROOT_APPS, Severity.LOW,
            "Apps whose package names contain oplu or oplusex are treated as low-severity vendor utilities unless stronger root evidence also exists",
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
        val (regularFound, _) = splitOplusMatches(found)
        return listOf(det(
            "root_binaries", "Root Binaries", DetectionCategory.BUSYBOX, Severity.HIGH,
            "Searches for su, busybox, magisk, resetprop, KernelSU and APatch binaries in extended paths",
            regularFound.isNotEmpty(), regularFound.take(10).joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkWritablePaths(): List<DetectionItem> {
        val writable = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        val protectedPaths = protectedSystemPaths
        protectedPaths.forEach { path ->
            if (!trustedLocked && runCatching { File(path).canWrite() }.getOrDefault(false)) {
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
                val exactProtectedMount = protectedPaths.contains(mountPoint)
                val nestedProtectedMount = protectedPaths.any { mountPoint.startsWith("$it/") }
                if (exactProtectedMount || nestedProtectedMount) {
                    val optionList = options.split(",")
                    val strongSignal = strongRootMountSignal("$device $fileSystem $options", mountPoint, trustedLocked)
                    val writableLike = optionList.any { it == "rw" } || fileSystem == "overlay" || device.contains("tmpfs") || device.contains("overlay") || device.contains("loop")
                    if (writableLike && ((!trustedLocked && exactProtectedMount) || strongSignal)) {
                        writable += "$mountPoint [$device $fileSystem $options]"
                    }
                }
            }
        } catch (_: Exception) {}
        val (regularWritable, _) = splitOplusMatches(writable)
        return listOf(det(
            "rw_paths", "Writable System Paths", DetectionCategory.WRITABLE_PATHS, Severity.HIGH,
            "System, vendor and product partitions should not be writable or overlaid on stock builds",
            regularWritable.isNotEmpty(), regularWritable.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMagiskFiles(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        magiskPaths.forEach { path ->
            if (File(path).exists()) {
                found += path
            }
        }
        val (regularFound, _) = splitOplusMatches(found)
        return listOf(det(
            "magisk_files", "Magisk / KSU / APatch Files", DetectionCategory.MAGISK, Severity.HIGH,
            "Checks Magisk, KernelSU and APatch artifacts under /data/adb, /dev and ramdisk mirrors",
            regularFound.isNotEmpty(), regularFound.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkOplusDirectories(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        val candidatePaths = linkedSetOf<String>()
        candidatePaths += suPaths
        candidatePaths += magiskPaths
        dangerousBinaries.forEach { bin ->
            binaryPaths.forEach { path ->
                candidatePaths += "$path$bin"
            }
        }
        candidatePaths.filter(::isOplusMarker).forEach { path ->
            if (File(path).exists()) {
                found += path
            }
        }
        try {
            File("/proc/mounts").forEachLine { line ->
                val lower = line.lowercase()
                if (isOplusMarker(lower)) {
                    found += line.take(160)
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "oplus_dirs", "Oplus / OplusEx Directories", DetectionCategory.MOUNT_POINTS, Severity.LOW,
            "Directories and mount entries containing oplu or oplusex are treated as low severity unless direct root markers also appear",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkFrida(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        fridaProcesses.forEach { name ->
            if (isProcessRunning(name)) {
                evidence += "process=$name"
            }
        }
        fridaPorts.forEach { port ->
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
        if (Build.PRODUCT in emulatorProducts) indicators += "PRODUCT=${Build.PRODUCT}"
        return listOf(det(
            "emulator", "Emulator / Virtual Device", DetectionCategory.EMULATOR, Severity.MEDIUM,
            "Exact emulator hardware/product/fingerprint signatures",
            indicators.isNotEmpty(), indicators.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMountPoints(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        val targets = protectedSystemPaths
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 4) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                val options = parts[3]
                val exactProtectedMount = targets.contains(mountPoint)
                val nestedProtectedMount = targets.any { mountPoint.startsWith("$it/") }
                val writable = options.split(",").any { it == "rw" }
                val suspiciousSource = device.startsWith("/dev/block/") || device.startsWith("dm-") || device.contains("overlay") || device.contains("tmpfs")
                val strongSignal = strongRootMountSignal("$device $fileSystem $options", mountPoint, trustedLocked)
                val suspiciousMount = writable || fileSystem == "overlay" || suspiciousSource && (device.contains("overlay") || device.contains("tmpfs") || device.contains("loop"))
                if ((exactProtectedMount || nestedProtectedMount) && suspiciousMount && ((!trustedLocked && exactProtectedMount) || strongSignal)) {
                    suspicious += "$mountPoint [$device $fileSystem $options]"
                }
            }
        } catch (_: Exception) {}
        val (regularSuspicious, _) = splitOplusMatches(suspicious)
        return listOf(det(
            "mount_rw", "RW System Mount Points", DetectionCategory.MOUNT_POINTS, Severity.HIGH,
            "/proc/mounts shows writable, overlaid or tmpfs-backed system partitions",
            regularSuspicious.isNotEmpty(), regularSuspicious.joinToString("\n").ifEmpty { null }
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
        val systemPaths = protectedSystemPaths.map { "$it/" } + "/apex/"
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
        val hasMagiskDevice = File("/dev/magisk").exists()
        val hasMagiskMirror = File("/sbin/.magisk").exists()
        if (hasMagiskDevice) evidence += "/dev/magisk exists"
        if (hasMagiskMirror) evidence += "/sbin/.magisk exists"
        var sawDebugRamdisk = false
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 3) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                if (fileSystem == "tmpfs" && mountPoint == "/sbin") evidence += "tmpfs on /sbin"
                if (mountPoint == "/debug_ramdisk") {
                    sawDebugRamdisk = true
                }
                if (DetectorTrust.hasExplicitMountRootMarker(line) || (line.contains("overlay") && line.contains("/data/adb"))) {
                    if (mountPoint.startsWith("/system") || mountPoint.startsWith("/vendor") || mountPoint.startsWith("/product") || mountPoint.startsWith("/odm")) {
                        evidence += "$mountPoint [$device $fileSystem]"
                    }
                }
            }
        } catch (_: Exception) {}
        if (sawDebugRamdisk && (hasMagiskDevice || hasMagiskMirror || evidence.any { it.contains("/data/adb") || it.contains(".magisk") })) {
            evidence += "/debug_ramdisk present with root staging traces"
        }
        val (regularEvidence, _) = splitOplusMatches(evidence)
        return listOf(det(
            "magisk_tmpfs", "Magisk tmpfs / debug_ramdisk", DetectionCategory.MAGISK, Severity.HIGH,
            "Looks for Magisk ramdisk mirrors, tmpfs staging points and overlay-backed mounts",
            regularEvidence.isNotEmpty(), regularEvidence.joinToString("\n").ifEmpty { null }
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
        kernelSuPackages.forEach { pkg ->
            if (isPackageInstalled(context.packageManager, pkg)) {
                evidence += "package $pkg"
            }
        }
        kernelSuPaths.forEach { path ->
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
        val knownDangerous = knownDangerousModules
        val detectedModules = linkedSetOf<String>()
        val genericModules = linkedSetOf<String>()
        val scanFiles = moduleScanFiles
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
        val (regularFound, _) = splitOplusMatches(found)
        return listOf(det(
            "su_in_path", "SU in \$PATH", DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Walks PATH for su binaries and root-specific executable directories",
            regularFound.isNotEmpty(), regularFound.joinToString("\n").ifEmpty { null }
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
        managerActions.forEach { action ->
            try {
                val resolved = pm.queryIntentActivities(Intent(action), PackageManager.MATCH_DEFAULT_ONLY)
                if (resolved.isNotEmpty()) {
                    resolved.mapNotNull { it.activityInfo?.packageName }.forEach { anomalies += "$action -> $it" }
                }
            } catch (_: Exception) {}
        }
        val (regularAnomalies, _) = splitOplusMatches(anomalies)
        return listOf(det(
            "pm_anomalies", "Package Manager Check", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Scans installed packages, launch intents and known manager actions for hidden root apps",
            regularAnomalies.isNotEmpty(), regularAnomalies.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun frameworkKeywords(): List<String> = DetectorTrust.frameworkKeywords()

    private fun isOplusMarker(value: String): Boolean = DetectorTrust.isOplusMarker(value)

    private fun splitOplusMatches(values: Collection<String>): Pair<List<String>, List<String>> {
        val regular = mutableListOf<String>()
        val oplus = mutableListOf<String>()
        values.forEach { value ->
            if (isOplusMarker(value)) {
                oplus += value
            } else {
                regular += value
            }
        }
        return regular to oplus
    }

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
            kernelCmdlineFlags.forEach { flag ->
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
            val env = envKeys.associateWith { System.getenv(it) }
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
        val keywords = devSocketKeywords
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
                Severity.MEDIUM,
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
        val capEff = readStatusValue("CapEff")
        if (!capEff.isNullOrEmpty()) {
            val caps = capEff.toLongOrNull(16) ?: 0L
            val dangerousCaps = 0x0000000000000001L or
                    0x0000000000000002L or
                    0x0000000000000004L or
                    0x0000000000002000L or
                    0x0000000000004000L or
                    0x0000000000008000L or
                    0x0000000000200000L
            val rootLevelCaps = 0x3fffffffffffffffL
            if (caps and dangerousCaps != 0L || caps >= rootLevelCaps) {
                elevated += "CapEff=0x$capEff (elevated effective capabilities)"
            }
        }
        return listOf(
            det(
                "process_caps",
                "Linux Capabilities",
                DetectionCategory.SYSTEM_PROPS,
                Severity.HIGH,
                "Process has dangerous effective Linux capabilities — indicates root or escalation",
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
                val protectedMount = protectedSystemPaths.any { mountPoint.startsWith(it) }
                if (protectedMount && strongRootMountSignal("$device [$fileSystem]", mountPoint, trustedLocked)) {
                    mounts += "$device -> $mountPoint [$fileSystem]"
                }
            }
        } catch (_: Exception) {}
        val (regularMounts, _) = splitOplusMatches(mounts)
        return listOf(
            det(
                "suspicious_mount",
                "Suspicious System Mount Source",
                DetectionCategory.MOUNT_POINTS,
                Severity.HIGH,
                "System partitions should not be backed by overlay, tmpfs or loop devices",
                regularMounts.isNotEmpty(),
                regularMounts.joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkBinderServices(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val exactDangerousServices = setOf(
            "magiskd", "zygiskd", "zygisk", "tricky_store", "trickystore",
            "ksud", "kernelsu", "lsposed", "lspd", "riru"
        )
        try {
            val process = Runtime.getRuntime().exec("service list")
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)
            output.lineSequence().forEach { line ->
                val lower = line.lowercase()
                if (exactDangerousServices.any { svc ->
                    Regex("""(^|[^a-z0-9_])${Regex.escape(svc)}([^a-z0-9_]|$)""").containsMatchIn(lower)
                }) {
                    suspicious += line.trim().take(160)
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "binder_services",
                "Runtime Service List",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Looks for exact root daemon service names in Android binder service list",
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
        val keywords = hiddenModuleKeywords
        val scanFiles = moduleScanFiles
        try {
            moduleDirs.forEach { dirPath ->
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
                    if (DetectorTrust.shouldTrackSensitiveMount(mountPoint)) {
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
        val warrantyBit = getProp("ro.boot.warranty_bit").lowercase().ifEmpty { getProp("ro.warranty_bit").lowercase() }
        val secureBootLock = getProp("ro.secureboot.lockstate").lowercase()

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
        if (warrantyBit == "1" && flashLocked == "0") {
            suspicious += "warranty bit tripped and bootloader unlocked"
        }
        if (secureBootLock == "unlocked" && flashLocked == "1") {
            suspicious += "secureboot lockstate says unlocked while flash state says locked"
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
        val keywords = hideBypassKeywords
        val scanFiles = moduleScanFiles + listOf("action.sh", "system.prop")

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

    private fun checkHardcodedFrameworkSweep(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        val keywords = frameworkSweepKeywords
        val mountKeywords = setOf("magisk", "zygisk", "kernelsu", "ksu", "apatch", "shamiko", "trickystore", "playintegrityfix", "susfs")
        val exactServiceMarkers = setOf("magiskd", "zygiskd", "lsposed", "riru", "tricky_store", "trickystore", "kernelsu", "ksud", "apatch")
        val exactPropMarkers = setOf("magisk", "zygisk", "kernelsu", "ksu", "apatch", "shamiko", "trickystore", "playintegrityfix", "resetprop", "susfs")
        val exactRuntimeMarkers = setOf("magisk", "magiskd", "zygisk", "zygiskd", "lsposed", "riru", "lspd", "kernelsu", "ksud", "apatch", "shamiko", "trickystore", "susfs", "resetprop")
        val groupedSources = linkedSetOf<String>()
        var criticalHits = 0
        var mountHit = false

        fun sourceGroup(source: String): String = when {
            source.startsWith("maps") -> "maps"
            source.startsWith("mount") -> "mounts"
            else -> source
        }

        fun containsToken(text: String, token: String): Boolean {
            return Regex("""(^|[^a-z0-9_])${Regex.escape(token)}([^a-z0-9_]|$)""").containsMatchIn(text)
        }

        fun collectHits(source: String, lines: Sequence<String>, limit: Int) {
            lines.forEach { raw ->
                val line = raw.trim()
                val lower = line.lowercase()
                val hits = keywords.filter { lower.contains(it) }
                if (hits.isNotEmpty()) {
                    val rootedMount = source.startsWith("mount") &&
                        mountKeywords.any { containsToken(lower, it) } &&
                        (lower.contains("/data/adb") || lower.contains("/debug_ramdisk") || lower.contains("/.magisk") || lower.contains("/sbin") || lower.contains("overlay"))
                    val runtimeMarkerHit = exactRuntimeMarkers.any { containsToken(lower, it) }
                    val exactPropLeak = source == "getprop" &&
                        exactPropMarkers.any { containsToken(lower, it) } &&
                        (line.contains("[") || line.contains("ro.") || line.contains("persist.") || line.contains("vendor."))
                    val exactServiceLeak = source == "service" &&
                        exactServiceMarkers.any {
                            containsToken(lower, it)
                        }
                    val mappedLeak = source.startsWith("maps") &&
                        runtimeMarkerHit &&
                        (lower.contains("/data/adb") || lower.contains("/debug_ramdisk") || lower.contains("/sbin") || lower.contains("memfd:") || lower.contains("(deleted)"))
                    val unixLeak = source == "unix" &&
                        runtimeMarkerHit &&
                        (lower.contains("@") || lower.contains("/dev/") || lower.contains("socket"))
                    val confirmed = rootedMount || exactPropLeak || exactServiceLeak || mappedLeak || unixLeak
                    if (confirmed) {
                        evidence += "$source ${hits.take(3).joinToString(",")} -> ${line.take(140)}"
                        groupedSources += sourceGroup(source)
                        criticalHits++
                        if (rootedMount) mountHit = true
                    }
                }
                if (evidence.size >= limit) return
            }
        }

        try {
            collectHits("maps:self", File("/proc/self/maps").useLines { it.toList().asSequence() }, 6)
        } catch (_: Exception) {}
        try {
            collectHits("maps:init", File("/proc/1/maps").useLines { it.toList().asSequence() }, 10)
        } catch (_: Exception) {}
        try {
            collectHits("unix", File("/proc/net/unix").useLines { it.toList().asSequence() }, 14)
        } catch (_: Exception) {}
        try {
            collectHits("mounts", File("/proc/mounts").useLines { it.toList().asSequence() }, 18)
        } catch (_: Exception) {}
        try {
            collectHits("mountinfo", File("/proc/1/mountinfo").useLines { it.toList().asSequence() }, 22)
        } catch (_: Exception) {}
        try {
            val output = Runtime.getRuntime().exec("getprop").inputStream.bufferedReader().readText()
            collectHits("getprop", output.lineSequence(), 26)
        } catch (_: Exception) {}
        try {
            val output = Runtime.getRuntime().exec("service list").inputStream.bufferedReader().readText()
            collectHits("service", output.lineSequence(), 30)
        } catch (_: Exception) {}

        val detected = mountHit ||
            (groupedSources.contains("maps") && groupedSources.contains("unix")) ||
            (!trustedLocked && groupedSources.contains("maps") && criticalHits >= 2)

        return listOf(
            det(
                "hardcoded_framework_sweep",
                "Runtime Artifact Sweep",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Cross-checks root framework traces across memory maps, sockets, mounts, services and properties",
                detected,
                evidence.take(10).joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkLineageServices(): List<DetectionItem> {
        val detected = linkedSetOf<String>()
        try {
            val process = Runtime.getRuntime().exec("service list")
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)
            output.lineSequence().forEach { line ->
                val lower = line.lowercase()
                lineageServices.filter { svc ->
                    lower.contains(svc.lowercase()) &&
                    !lower.contains("pixel") &&
                    !lower.contains("google")
                }.forEach { _ ->
                    detected += line.trim().take(160)
                }
            }
        } catch (_: Exception) {}
        return listOf(
            det(
                "lineage_services",
                "LineageOS Services",
                DetectionCategory.CUSTOM_ROM,
                Severity.MEDIUM,
                "Scans binder service list for LineageOS hardware, health, livedisplay and touch services",
                detected.isNotEmpty(),
                detected.take(10).joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkLineagePermissions(): List<DetectionItem> {
        val detected = linkedSetOf<String>()
        val pm = context.packageManager
        lineagePermissions.forEach { permission ->
            try {
                pm.getPermissionInfo(permission, 0)
                detected += permission
            } catch (_: Exception) {}
        }
        return listOf(
            det(
                "lineage_permissions",
                "LineageOS Platform Permissions",
                DetectionCategory.CUSTOM_ROM,
                Severity.MEDIUM,
                "Checks for LineageOS-specific platform permissions exposed by the framework",
                detected.isNotEmpty(),
                detected.joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkLineageInitFiles(): List<DetectionItem> {
        val detected = linkedSetOf<String>()
        lineageInitFiles.forEach { path ->
            if (File(path).exists()) {
                detected += path
            }
        }
        return listOf(
            det(
                "lineage_files",
                "LineageOS Init / Framework Files",
                DetectionCategory.CUSTOM_ROM,
                Severity.MEDIUM,
                "Checks for LineageOS init rc, platform xml and framework jar artifacts",
                detected.isNotEmpty(),
                detected.joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkLineageSepolicy(): List<DetectionItem> {
        val detected = linkedSetOf<String>()
        lineageSepolicyFiles.forEach { path ->
            val file = File(path)
            if (!file.exists() || !file.canRead()) return@forEach
            val content = runCatching { file.readText() }.getOrDefault("")
            val lower = content.lowercase()
            val count = Regex("lineage").findAll(lower).count()
            if (count > 0) {
                detected += "$path contains 'lineage' $count times"
            }
        }
        return listOf(
            det(
                "lineage_sepolicy",
                "LineageOS Sepolicy Traces",
                DetectionCategory.CUSTOM_ROM,
                Severity.MEDIUM,
                "Scans readable sepolicy cil files for repeated lineage markers",
                detected.isNotEmpty(),
                detected.joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkCustomRom(): List<DetectionItem> {
        val indicators = linkedSetOf<String>()
        var strongSignals = 0

        customRomProps.forEach { (prop, rom) ->
            val v = getProp(prop)
            if (v.isNotEmpty()) {
                indicators += "$rom ($v)"
                strongSignals++
            }
        }

        val buildFields = listOf(
            "FINGERPRINT" to (android.os.Build.FINGERPRINT ?: ""),
            "DISPLAY" to (android.os.Build.DISPLAY ?: ""),
            "DESCRIPTION" to getProp("ro.build.description"),
            "PRODUCT" to (android.os.Build.PRODUCT ?: ""),
            "DEVICE" to (android.os.Build.DEVICE ?: ""),
            "BRAND" to (android.os.Build.BRAND ?: ""),
            "MANUFACTURER" to (android.os.Build.MANUFACTURER ?: "")
        )
        val searchableKeywords = setOf(
            "lineage",
            "crdroid",
            "evolution",
            "evox",
            "pixelos",
            "yaap",
            "pixel experience",
            "pixelexperience",
            "derpfest",
            "rising",
            "matrixx",
            "nameless",
            "aicp",
            "syberia",
            "awaken",
            "pixys",
            "phhgsi"
        )

        fun containsRomToken(text: String, keyword: String): Boolean {
            val escaped = Regex.escape(keyword.lowercase()).replace("\\ ", "\\\\s+")
            return Regex("(^|[^a-z0-9])$escaped([^a-z0-9]|$)", RegexOption.IGNORE_CASE).containsMatchIn(text)
        }

        buildFields.forEach { (field, value) ->
            val lower = value.lowercase()
            customRomKeywords.forEach { (keyword, name) ->
                if (keyword in searchableKeywords && containsRomToken(lower, keyword)) {
                    indicators += "$name in $field"
                }
            }
        }

        runCatching {
            val allProps = Runtime.getRuntime().exec("getprop").inputStream.bufferedReader().readText().lowercase()
            customRomKeywords.forEach { (keyword, name) ->
                if (keyword in searchableKeywords && containsRomToken(allProps, keyword)) {
                    indicators += "$name in getprop"
                }
            }
        }

        customRomFiles.forEach { path ->
            if (java.io.File(path).exists()) {
                indicators += path
                strongSignals++
            }
        }

        val detected = strongSignals > 0 || indicators.size >= 2
        return listOf(det(
            "custom_rom", "Aftermarket ROM", DetectionCategory.CUSTOM_ROM, Severity.MEDIUM,
            "Looks for custom ROM props, framework files and stronger build identifiers from popular aftermarket ROMs",
            detected, indicators.joinToString("\n").ifEmpty { null }
        ))
    }
    private fun checkTmpfsOnData(): List<DetectionItem> {
        val found = linkedSetOf<String>()
        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 3) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fs = parts[2]
                if (fs == "tmpfs" && (
                    mountPoint.startsWith("/data/adb") ||
                    mountPoint == "/debug_ramdisk" ||
                    mountPoint.startsWith("/sbin")
                )) {
                    found += "$mountPoint [tmpfs from $device]"
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "tmpfs_data", "Suspicious tmpfs on Data Paths", DetectionCategory.MOUNT_POINTS, Severity.HIGH,
            "tmpfs mounted over /data/adb or /debug_ramdisk is a strong Magisk/KSU staging signal",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSuTimestamps(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val recentThresholdMs = 30L * 24 * 60 * 60 * 1000
        val now = System.currentTimeMillis()
        val pathsToCheck = listOf(
            "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap",
            "/data/adb/modules", "/debug_ramdisk"
        )
        pathsToCheck.forEach { path ->
            val f = java.io.File(path)
            if (f.exists()) {
                val age = now - f.lastModified()
                if (age < recentThresholdMs && f.lastModified() > 0) {
                    suspicious += "$path (modified ${age / 86400000}d ago)"
                }
            }
        }
        return listOf(det(
            "su_timestamps", "Recent Root Artifact Timestamps", DetectionCategory.MAGISK, Severity.HIGH,
            "Root artifacts modified within the last 30 days indicate active root installation",
            suspicious.isNotEmpty(), suspicious.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkApkInstallSource(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        try {
            val pm = context.packageManager
            val myPackage = context.packageName
            val installer = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(myPackage).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(myPackage)
            }
            val knownStores = setOf(
                "com.android.vending", "com.google.android.packageinstaller",
                "com.samsung.android.packageinstaller", "com.miui.packageinstaller",
                "com.huawei.appmarket", "com.xiaomi.market"
            )
            if (installer == null) {
                suspicious += "APK installed via ADB or unknown source (no installer recorded)"
            } else if (installer !in knownStores) {
                suspicious += "Installed by: $installer (not a known app store)"
            }
        } catch (_: Exception) {}
        return listOf(det(
            "install_source", "APK Install Source", DetectionCategory.BUILD_TAGS, Severity.LOW,
            "Apps installed via ADB or sideloading may indicate a developer or testing environment",
            suspicious.isNotEmpty(), suspicious.joinToString("\n").ifEmpty { null }
        ))
    }

}
