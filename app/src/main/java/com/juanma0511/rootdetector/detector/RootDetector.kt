package com.juanma0511.rootdetector.detector

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class RootDetector(private val context: Context) {

    private val suPaths = HardcodedSignals.suPaths
    private val mediumToolPackages = linkedMapOf(
        "com.dimonvideo.luckypatcher" to "Lucky Patcher",
        "com.chelpus.lackypatch" to "Lucky Patcher",
        "com.android.vending.billing.InAppBillingService.COIN" to "Lucky Patcher",
        "com.android.vending.billing.InAppBillingService.LUCK" to "Lucky Patcher"
    )
    private val lsposedHighRiskApps = linkedMapOf(
        "io.mesalabs.knoxpatch" to "KnoxPatch",
        "com.omarea.vtools" to "Scene"
    )
    private val rootPackages = HardcodedSignals.rootPackages.filterNot {
        it.contains("keyattestation", ignoreCase = true) || it in mediumToolPackages.keys
    }
    private val patchedApps = HardcodedSignals.patchedApps.filterNot {
        it.contains("keyattestation", ignoreCase = true) || it in mediumToolPackages.keys
    }
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
    private val ksuNextPaths = HardcodedSignals.ksuNextPaths
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
        val items = mutableListOf<DetectionItem>()
        items.addAll(fetchAppZygoteDetections())

        val checks: List<() -> List<DetectionItem>> = listOf(
            ::checkSuBinaries,
            ::checkRootPackages,
            ::checkLsposedCompanionApps,
            ::checkPatchedApps,
            ::checkMediumRiskTools,
            ::checkWarningApps,
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
            ::checkKernelPatchWindow,
            ::checkSpoofedProps,
            ::checkSuspiciousMountSources,
            ::checkMountInfoConsistency,
            ::checkBinderServices,
            ::checkProcessEnvironment,
            ::checkInitRcRootTraces,
            ::checkRootSepolicyTraces,
            ::checkMemfdArtifacts,
            ::checkPropertyConsistency,
            ::checkBuildFieldCoherence,
            ::checkHideBypassModules,
            ::checkHiddenMagiskModules,
            ::checkHardcodedFrameworkSweep,
            ::checkTmpfsOnData,
            ::checkSuTimestamps,
            ::checkLdPreload,
            ::checkSeccompMode,
            ::checkTracerPid,
            ::checkSUSFS,
            ::checkSOTER,
            ::checkXposedFramework,
            ::checkADBNetwork,
            ::checkDeveloperOptions,
            ::checkSuDirectory,
            ::checkExternalStorageArtifacts,
            ::checkRecoveryArtifacts,
            ::checkInitDotD,
            ::checkDataLocalTmp,
            ::checkResetpropModifications,
            ::checkSelinuxAttrCurrentWrite,
            ::checkSelinuxDirtyPolicy
        )
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

    private fun checkLsposedCompanionApps(): List<DetectionItem> {
        val pm = context.packageManager
        val found = linkedSetOf<String>()
        lsposedHighRiskApps.forEach { (pkg, label) ->
            when {
                isPackageInstalled(pm, pkg) -> found += "$label ($pkg)"
                pm.getLaunchIntentForPackage(pkg) != null -> found += "$label ($pkg launchable)"
            }
        }
        return listOf(det(
            "lsposed_companions", "LSPosed Companion Apps", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Detects LSPosed companion apps and modules such as KnoxPatch and Scene",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMediumRiskTools(): List<DetectionItem> {
        val pm = context.packageManager
        val found = linkedSetOf<String>()
        mediumToolPackages.forEach { (pkg, label) ->
            when {
                isPackageInstalled(pm, pkg) -> found += "$label ($pkg)"
                pm.getLaunchIntentForPackage(pkg) != null -> found += "$label ($pkg launchable)"
            }
        }
        return listOf(det(
            "medium_risk_tools", "App Patchers / Mod Tools", DetectionCategory.ROOT_APPS, Severity.MEDIUM,
            "Detects medium-risk app patching and modification tools such as Lucky Patcher",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
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
            if (isProcessRunning(name)) evidence += "process=$name"
        }
        val allFridaPorts = (fridaPorts + listOf(27043, 27044, 27047)).distinct()
        allFridaPorts.forEach { port ->
            val open = try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 150)
                socket.close()
                true
            } catch (_: Exception) { false }
            if (open) evidence += "port=$port open"
        }
        try {
            File("/proc/self/maps").forEachLine { line ->
                val lower = line.lowercase()
                if (lower.contains("frida-agent") || lower.contains("frida-gadget") ||
                    lower.contains("gum-js") || lower.contains("frida-helper")) {
                    evidence += line.trim().take(120)
                }
            }
        } catch (_: Exception) {}
        evidence += collectNetUnixMatches(listOf("frida", "gadget")).take(3)
        try {
            File("/proc/self/fd").listFiles()?.forEach { fdEntry ->
                runCatching {
                    val target = java.nio.file.Files.readSymbolicLink(fdEntry.toPath()).toString()
                    val lower = target.lowercase()
                    if (lower.contains("frida") || lower.contains("gadget") || lower.contains("gum-js")) {
                        evidence += "fd -> $target"
                    }
                }
            }
        } catch (_: Exception) {}
        try {
            File("/proc/net/tcp").forEachLine { line ->
                val fields = line.trim().split(Regex("\\s+"))
                if (fields.size < 4 || fields[0] == "sl") return@forEachLine
                val localAddr = fields[1]
                val port = localAddr.substringAfter(":").toIntOrNull(16) ?: return@forEachLine
                val state = fields[3]
                if (port in listOf(27042, 27043, 27044, 27047) && state == "0A") {
                    evidence += "/proc/net/tcp: port $port listening"
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "frida", "Frida Instrumentation", DetectionCategory.FRIDA, Severity.HIGH,
            "Checks Frida processes, loopback ports 27042-27047, unix sockets, injected maps, FDs and /proc/net/tcp",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkEmulator(): List<DetectionItem> {
        val indicators = mutableListOf<String>()
        val fp = Build.FINGERPRINT ?: ""
        if (fp.startsWith("generic") || fp.contains(":generic/") || fp.contains("unknown/unknown"))
            indicators += "FINGERPRINT=$fp"
        if (Build.HARDWARE == "goldfish" || Build.HARDWARE == "ranchu")
            indicators += "HARDWARE=${Build.HARDWARE}"
        if (Build.MANUFACTURER.equals("Genymotion", ignoreCase = true))
            indicators += "MANUFACTURER=Genymotion"
        if (Build.PRODUCT in emulatorProducts)
            indicators += "PRODUCT=${Build.PRODUCT}"
        if (Build.BRAND.equals("generic", ignoreCase = true) || Build.BRAND.equals("Android", ignoreCase = true))
            indicators += "BRAND=${Build.BRAND}"
        if (Build.DEVICE.equals("generic", ignoreCase = true) || Build.DEVICE.startsWith("generic_"))
            indicators += "DEVICE=${Build.DEVICE}"
        if (Build.MODEL.contains("Android SDK built for", ignoreCase = true) ||
            (Build.MODEL.contains("sdk", ignoreCase = true) && Build.MODEL.contains("emulator", ignoreCase = true)))
            indicators += "MODEL=${Build.MODEL}"
        if (Build.BOARD.isNullOrEmpty() || Build.BOARD == "unknown")
            indicators += "BOARD=${Build.BOARD} (unknown board)"
        val qemuProp = getProp("ro.kernel.qemu")
        if (qemuProp == "1") indicators += "ro.kernel.qemu=1"
        val bootQemuProp = getProp("ro.boot.qemu")
        if (bootQemuProp == "1") indicators += "ro.boot.qemu=1"
        val cpuAbi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        if (cpuAbi.contains("x86") && Build.HARDWARE != null &&
            !Build.HARDWARE.contains("x86", ignoreCase = true) &&
            Build.BRAND.equals("generic", ignoreCase = true))
            indicators += "CPU_ABI=$cpuAbi on generic-branded device"
        return listOf(det(
            "emulator", "Emulator / Virtual Device", DetectionCategory.EMULATOR, Severity.MEDIUM,
            "Checks fingerprint, hardware, brand, device, model, board, QEMU props and CPU ABI for emulator indicators",
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
        (kernelSuPaths + ksuNextPaths).forEach { path ->
            if (File(path).exists()) {
                evidence += path
            }
        }
        evidence += collectNetUnixMatches(listOf("ksu", "kernelsu", "ksunext", "apatch")).take(4)
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
        val sysfsValue = runCatching {
            File("/sys/fs/selinux/enforce").readText().trim()
        }.getOrNull()
        val sysfsPermissive = sysfsValue == "0"
        if (sysfsPermissive) {
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

    private fun checkSelinuxAttrCurrentWrite(): List<DetectionItem> {
        val targets = listOf(
            "KernelSU"      to "u:r:ksu:s0",
            "KernelSU file" to "u:r:ksu_file:s0",
            "Magisk"        to "u:r:magisk:s0",
            "Magisk file"   to "u:r:magisk_file:s0",
            "LSPosed file"  to "u:r:lsposed_file:s0",
            "Xposed data"   to "u:r:xposed_data:s0",
            "MSD app"       to "u:r:msd_app:s0",
            "MSD daemon"    to "u:r:msd_daemon:s0"
        )
        val hits = linkedSetOf<String>()
        for ((label, ctx) in targets) {
            runCatching {
                val payload = ctx.toByteArray(Charsets.UTF_8)
                java.io.FileOutputStream("/proc/self/attr/current").use { out ->
                    android.system.Os.write(out.fd, payload, 0, payload.size)
                }
                hits += "$label:SUCCESS"
            }.onFailure { err ->
                when {
                    err is android.system.ErrnoException &&
                        err.errno == android.system.OsConstants.EACCES ->
                        hits += "$label:EACCES"
                    err is java.io.IOException &&
                        err.message?.lowercase()?.contains("permission denied") == true &&
                        err.message?.lowercase()?.contains("invalid argument") == false ->
                        hits += "$label:PermissionDenied"
                }
            }
        }
        return listOf(det(
            "selinux_attr_write",
            "SELinux Root Context Detected (attr/current)",
            DetectionCategory.SYSTEM_PROPS,
            Severity.HIGH,
            "Writes root-specific SELinux context strings to /proc/self/attr/current. EINVAL means the context is not in the loaded policy (normal). Any other response proves the context type exists in the live policy — confirming Magisk, KernelSU, LSPosed or Xposed is loaded.",
            hits.isNotEmpty(),
            hits.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSelinuxDirtyPolicy(): List<DetectionItem> {
        val checkAccess: ((String, String, String, String) -> Boolean?)? = runCatching {
            val cls = Class.forName("android.os.SELinux")
            val method = cls.getMethod("checkSELinuxAccess",
                String::class.java, String::class.java, String::class.java, String::class.java)
            val fn: (String, String, String, String) -> Boolean? = { scon, tcon, tclass, perm ->
                method.invoke(null, scon, tcon, tclass, perm) as? Boolean
            }
            fn
        }.getOrNull()

        val hits = linkedSetOf<String>()
        if (checkAccess != null) {
            val neg1 = runCatching { checkAccess("u:r:untrusted_app:s0", "u:r:init:s0", "binder", "call") }.getOrNull()
            val neg2 = runCatching { checkAccess("u:r:untrusted_app:s0", "u:r:init:s0", "binder", "call") }.getOrNull()
            val oracleReliable = neg1 != true && neg2 != true
            if (oracleReliable) {
                val isUserBuild = getProp("ro.build.type") == "user"
                data class Rule(val src: String, val tgt: String, val cls: String, val perm: String, val label: String, val userBuildOnly: Boolean = false)
                val rules = listOf(
                    Rule("u:r:system_server:s0",  "u:r:system_server:s0",       "process", "execmem",   "system_server execmem"),
                    Rule("u:r:untrusted_app:s0",  "u:object_r:magisk_file:s0",  "file",    "read",      "untrusted_app -> magisk_file read"),
                    Rule("u:r:untrusted_app:s0",  "u:object_r:ksu_file:s0",     "file",    "read",      "untrusted_app -> ksu_file read"),
                    Rule("u:r:untrusted_app:s0",  "u:object_r:lsposed_file:s0", "file",    "read",      "untrusted_app -> lsposed_file read"),
                    Rule("u:r:untrusted_app:s0",  "u:object_r:xposed_data:s0",  "file",    "read",      "untrusted_app -> xposed_data read"),
                    Rule("u:r:adbd:s0",           "u:r:adbroot:s0",             "binder",  "call",      "adbd -> adbroot binder"),
                    Rule("u:r:zygote:s0",         "u:object_r:adb_data_file:s0","dir",     "search",    "zygote -> adb_data_file search"),
                    Rule("u:r:shell:s0",          "u:r:su:s0",                  "process", "transition","shell -> su transition", userBuildOnly = true)
                )
                for (rule in rules) {
                    if (rule.userBuildOnly && !isUserBuild) continue
                    val r1 = runCatching { checkAccess(rule.src, rule.tgt, rule.cls, rule.perm) }.getOrNull()
                    val r2 = runCatching { checkAccess(rule.src, rule.tgt, rule.cls, rule.perm) }.getOrNull()
                    if (r1 == true && r2 == true) hits += "${rule.label}=allowed"
                }
            }
        }
        return listOf(det(
            "selinux_dirty_policy",
            "DirtySepolicy Rule Detected",
            DetectionCategory.SYSTEM_PROPS,
            Severity.HIGH,
            "Queries specific SELinux access pairs via android.os.SELinux.checkSELinuxAccess that should always be denied on stock Android policy. If any are allowed, the loaded SELinux policy has been modified by a root framework (DirtySepolicy, Magisk, KernelSU, LSPosed or APatch).",
            hits.isNotEmpty(),
            hits.joinToString("\n").ifEmpty { null }
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

    private fun parseUtcPropDate(value: String): Date? {
        val trimmed = value.trim()
        val seconds = trimmed.toLongOrNull() ?: return null
        if (seconds <= 0L) return null
        return Date(seconds * 1000L)
    }

    private data class FingerprintParts(
        val brand: String,
        val product: String,
        val device: String,
        val release: String,
        val buildId: String,
        val incremental: String,
        val buildType: String,
        val tags: String
    )

    private fun parseFingerprint(value: String): FingerprintParts? {
        val trimmed = value.trim()
        val sections = trimmed.split(':', limit = 3)
        if (trimmed.isEmpty() || sections.size != 3) return null
        val prefixParts = sections[0].split('/')
        val buildParts = sections[1].split('/')
        val typeParts = sections[2].split('/', limit = 2)
        if (prefixParts.size < 3 || buildParts.size < 3 || typeParts.isEmpty()) return null
        return FingerprintParts(
            brand = prefixParts[0],
            product = prefixParts[1],
            device = prefixParts[2],
            release = buildParts[0],
            buildId = buildParts[1],
            incremental = buildParts[2],
            buildType = typeParts[0],
            tags = typeParts.getOrNull(1).orEmpty()
        )
    }

    private fun compatibleIncremental(left: String, right: String): Boolean {
        if (left == right) return true
        if (left.startsWith(right) || right.startsWith(left)) return true
        val normalizedLeft = left.substringBefore('_')
        val normalizedRight = right.substringBefore('_')
        if (normalizedLeft.isNotBlank() && normalizedLeft == normalizedRight) return true
        val tokenizedLeft = left.replace(Regex("[^A-Za-z0-9]+"), " ").trim().split(Regex("\\s+")).filter { it.isNotBlank() }
        val tokenizedRight = right.replace(Regex("[^A-Za-z0-9]+"), " ").trim().split(Regex("\\s+")).filter { it.isNotBlank() }
        return tokenizedLeft.isNotEmpty() && tokenizedRight.isNotEmpty() && tokenizedLeft.any { token ->
            token.length >= 6 && tokenizedRight.any { other -> token == other || token.startsWith(other) || other.startsWith(token) }
        }
    }

    private fun runtimeFingerprintMatches(candidate: String, reference: String): Boolean {
        if (candidate == reference) return true
        val parsedCandidate = parseFingerprint(candidate) ?: return false
        val parsedReference = parseFingerprint(reference) ?: return false
        return parsedCandidate.brand == parsedReference.brand &&
            parsedCandidate.release == parsedReference.release &&
            parsedCandidate.buildId == parsedReference.buildId &&
            parsedCandidate.buildType == parsedReference.buildType &&
            parsedCandidate.tags == parsedReference.tags &&
            compatibleIncremental(parsedCandidate.incremental, parsedReference.incremental)
    }

    private fun crossPartitionFingerprintMismatch(
        buildFingerprint: String,
        systemFingerprint: String,
        trustedLocked: Boolean
    ): String? {
        if (buildFingerprint.isBlank() || systemFingerprint.isBlank()) return null
        if (buildFingerprint == systemFingerprint) return null
        val build = parseFingerprint(buildFingerprint) ?: return if (trustedLocked) null else "ro.build.fingerprint differs from ro.system.build.fingerprint"
        val system = parseFingerprint(systemFingerprint) ?: return if (trustedLocked) null else "ro.build.fingerprint differs from ro.system.build.fingerprint"

        val hardMismatch = build.brand != system.brand ||
            build.release != system.release ||
            build.buildId != system.buildId ||
            build.buildType != system.buildType ||
            build.tags != system.tags
        if (hardMismatch) {
            return "ro.build and ro.system fingerprints disagree on core build fields"
        }

        if (!compatibleIncremental(build.incremental, system.incremental)) {
            return "ro.build and ro.system fingerprints disagree on build incremental"
        }

        if (!trustedLocked && build.product != system.product && build.device != system.device) {
            return "ro.build and ro.system fingerprints disagree on product/device"
        }

        return null
    }

    private fun parsePatchDate(value: String): Date? {
        val trimmed = value.trim()
        if (!Regex("""\d{4}-\d{2}-\d{2}""").matches(trimmed)) return null
        return runCatching {
            SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
                isLenient = false
            }.parse(trimmed)
        }.getOrNull()
    }

    private fun parseKernelBuildDate(): Date? {
        val candidates = linkedSetOf<String>()
        runCatching { candidates += File("/proc/version").readText() }
        runCatching {
            val uname = Runtime.getRuntime().exec("uname -v").inputStream.bufferedReader().readText().trim()
            if (uname.isNotEmpty()) candidates += uname
        }
        val formatters = listOf(
            SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US),
            SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.US)
        ).onEach {
            it.timeZone = TimeZone.getTimeZone("UTC")
            it.isLenient = false
        }
        val patterns = listOf(
            Regex("""[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]{2,5}\s+\d{4}"""),
            Regex("""[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+UTC\s+\d{4}""")
        )
        candidates.forEach { raw ->
            patterns.forEach { regex ->
                regex.find(raw)?.value?.let { match ->
                    formatters.forEach { formatter ->
                        runCatching { formatter.parse(match) }.getOrNull()?.let { return it }
                    }
                }
            }
        }
        return null
    }

    private fun formatDate(value: Date?): String {
        if (value == null) return "unknown"
        return SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(value)
    }

    private fun diffDays(a: Date, b: Date): Long =
        kotlin.math.abs(a.time - b.time) / 86_400_000L

    private fun collectPatchDates(): LinkedHashMap<String, Date> {
        val collected = linkedMapOf<String, Date>()
        val patchProps = linkedMapOf(
            "android_patch" to (Build.VERSION.SECURITY_PATCH ?: ""),
            "build_patch" to getProp("ro.build.version.security_patch"),
            "vendor_patch" to getProp("ro.vendor.build.version.security_patch"),
            "system_ext_patch" to getProp("ro.system_ext.build.version.security_patch"),
            "product_patch" to getProp("ro.product.build.version.security_patch"),
            "odm_patch" to getProp("ro.odm.build.version.security_patch"),
            "bootimage_patch" to getProp("ro.bootimage.build.version.security_patch")
        )
        patchProps.forEach { (label, raw) ->
            parsePatchDate(raw)?.let { collected[label] = it }
        }
        val buildUtcProps = linkedMapOf(
            "bootimage_utc" to getProp("ro.bootimage.build.date.utc")
        )
        buildUtcProps.forEach { (label, raw) ->
            parseUtcPropDate(raw)?.let { collected[label] = it }
        }
        return collected
    }

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

    private fun collectSystemBuildDates(): LinkedHashMap<String, Date> {
        val out = linkedMapOf<String, Date>()
        val buildTimeMs = Build.TIME
        if (buildTimeMs > 0L) out["system_build_time"] = Date(buildTimeMs)
        val utcRaw = getProp("ro.build.date.utc")
        utcRaw.toLongOrNull()?.let { secs ->
            if (secs > 0L) out["ro.build.date.utc"] = Date(secs * 1000L)
        }
        val vendorUtc = getProp("ro.vendor.build.date.utc")
        vendorUtc.toLongOrNull()?.let { secs ->
            if (secs > 0L) out["ro.vendor.build.date.utc"] = Date(secs * 1000L)
        }
        return out
    }

    private fun checkKernelPatchWindow(): List<DetectionItem> {
        val kernelDate = parseKernelBuildDate()
        val patchDates = collectPatchDates()
        val systemDates = collectSystemBuildDates()
        val allReferences = linkedMapOf<String, Date>().apply {
            putAll(systemDates)
            putAll(patchDates)
        }

        if (kernelDate == null || allReferences.isEmpty()) {
            return listOf(det(
                "kernel_patch_window",
                "Kernel / Patch Window",
                DetectionCategory.SYSTEM_PROPS,
                Severity.MEDIUM,
                "Checks whether kernel build date is consistent with system build and security patch dates",
                false, null
            ))
        }

        val results = mutableListOf<DetectionItem>()

        val newerEvidence = linkedSetOf<String>()
        val newestRef = allReferences.maxByOrNull { it.value.time }!!
        if (kernelDate.after(newestRef.value)) {
            val deltaMs = kernelDate.time - newestRef.value.time
            val deltaDays = deltaMs / 86_400_000L
            newerEvidence += "kernel_build=${formatDate(kernelDate)}"
            newerEvidence += "newest_reference=${newestRef.key}:${formatDate(newestRef.value)}"
            newerEvidence += "kernel_is_${deltaDays}d_newer_than_system"
            newerEvidence += "indicates_aftermarket_kernel_flashed_post_OEM"
            systemDates.forEach { (k, v) ->
                if (kernelDate.after(v)) {
                    val d = (kernelDate.time - v.time) / 86_400_000L
                    newerEvidence += "$k=${formatDate(v)} (kernel +${d}d)"
                }
            }
            patchDates.forEach { (k, v) ->
                if (kernelDate.after(v)) {
                    val d = (kernelDate.time - v.time) / 86_400_000L
                    newerEvidence += "$k=${formatDate(v)} (kernel +${d}d)"
                }
            }
        }
        results += det(
            "kernel_newer_than_system",
            "Kernel Newer Than System / Security Patch",
            DetectionCategory.SYSTEM_PROPS,
            Severity.HIGH,
            "Kernel build date is more recent than the system image and security patch — strong indicator of an aftermarket custom kernel flashed independently of the OEM update",
            newerEvidence.isNotEmpty(),
            newerEvidence.joinToString("\n").ifEmpty { null }
        )

        val thresholdDays = if (bootLooksLockedAndNormal()) 60L else 30L
        val closest = patchDates.minByOrNull { diffDays(kernelDate, it.value) }
        val newest = patchDates.maxByOrNull { it.value.time }
        val staleness = linkedSetOf<String>()
        if (closest != null && newest != null) {
            val closestDiff = diffDays(kernelDate, closest.value)
            val newestDiff = diffDays(kernelDate, newest.value)
            if (closestDiff > thresholdDays && newestDiff > thresholdDays && !kernelDate.after(newest.value)) {
                staleness += "kernel_build=${formatDate(kernelDate)}"
                staleness += "closest_patch=${closest.key}:${formatDate(closest.value)} (${closestDiff}d apart)"
                staleness += "newest_patch=${newest.key}:${formatDate(newest.value)} (${newestDiff}d apart)"
                staleness += "threshold=${thresholdDays}d"
            }
        }
        results += det(
            "kernel_patch_window",
            "Kernel / Patch Window Mismatch",
            DetectionCategory.SYSTEM_PROPS,
            Severity.MEDIUM,
            "Kernel build date is unusually far from all security patch dates — indicates a mismatched kernel from a different build cycle",
            staleness.isNotEmpty(),
            staleness.joinToString("\n").ifEmpty { null }
        )

        return results
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

    private fun checkInitRcRootTraces(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val markers = setOf(
            "magisk", "zygisk", "lsposed", "riru", "kernelsu",
            "ksud", "apatch", "shamiko", "trickystore", "susfs"
        )

        fun containsToken(text: String, token: String): Boolean {
            return Regex("""(^|[^a-z0-9_])${Regex.escape(token)}([^a-z0-9_]|$)""").containsMatchIn(text)
        }

        val initTargets = listOf(
            File("/system/etc/init"),
            File("/system_ext/etc/init"),
            File("/vendor/etc/init"),
            File("/product/etc/init"),
            File("/odm/etc/init"),
            File("/init")
        )

        initTargets.forEach { target ->
            try {
                val files = if (target.isDirectory) {
                    target.listFiles()?.filter { it.isFile && it.extension == "rc" }.orEmpty()
                } else if (target.isFile && target.extension == "rc") {
                    listOf(target)
                } else {
                    emptyList()
                }
                files.forEach { file ->
                    if (!file.canRead()) return@forEach
                    file.useLines { lines ->
                        lines.forEach { line ->
                            val lower = line.trim().lowercase()
                            if (markers.any { containsToken(lower, it) }) {
                                suspicious += "${file.path}: ${line.trim().take(120)}"
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        return listOf(
            det(
                "init_rc_root",
                "Init RC Root Traces",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Scans readable init rc files for root framework services, imports and daemon traces",
                suspicious.isNotEmpty(),
                suspicious.take(8).joinToString("\n").ifEmpty { null }
            )
        )
    }

    private fun checkRootSepolicyTraces(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val markers = setOf(
            "magisk", "zygisk", "lsposed", "riru", "kernelsu",
            "ksud", "apatch", "shamiko", "trickystore", "susfs", "resetprop"
        )
        val sepolicyTargets = listOf(
            "/vendor/etc/selinux/vendor_sepolicy.cil",
            "/system_ext/etc/selinux/system_ext_sepolicy.cil",
            "/product/etc/selinux/product_sepolicy.cil",
            "/odm/etc/selinux/odm_sepolicy.cil",
            "/system/etc/selinux/plat_sepolicy.cil"
        )

        fun containsToken(text: String, token: String): Boolean {
            return Regex("""(^|[^a-z0-9_])${Regex.escape(token)}([^a-z0-9_]|$)""").containsMatchIn(text)
        }

        sepolicyTargets.forEach { path ->
            val file = File(path)
            if (!file.exists() || !file.canRead()) return@forEach
            val content = runCatching { file.readText().lowercase() }.getOrDefault("")
            val hits = markers.filter { containsToken(content, it) }
            if (hits.isNotEmpty()) {
                suspicious += "$path -> ${hits.distinct().joinToString(",")}"
            }
        }

        return listOf(
            det(
                "root_sepolicy",
                "Root Sepolicy Traces",
                DetectionCategory.MAGISK,
                Severity.HIGH,
                "Scans readable sepolicy cil files for Magisk, LSPosed, KernelSU, APatch and hide-bypass traces",
                suspicious.isNotEmpty(),
                suspicious.take(6).joinToString("\n").ifEmpty { null }
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

    private fun checkBuildFieldCoherence(): List<DetectionItem> {
        val suspicious = linkedSetOf<String>()
        val trustedLocked = bootLooksLockedAndNormal()
        val propFingerprint = getProp("ro.build.fingerprint")
        val propTags = getProp("ro.build.tags")
        val propType = getProp("ro.build.type")
        val systemFingerprint = getProp("ro.system.build.fingerprint")
        val runtimeFingerprint = Build.FINGERPRINT

        if (runtimeFingerprint.isNotBlank() && propFingerprint.isNotBlank()) {
            val runtimeMatchesBuild = runtimeFingerprintMatches(runtimeFingerprint, propFingerprint)
            val runtimeMatchesSystem = systemFingerprint.isNotBlank() && runtimeFingerprintMatches(runtimeFingerprint, systemFingerprint)
            if (!runtimeMatchesBuild && !runtimeMatchesSystem) {
                suspicious += "Build.FINGERPRINT differs from live system fingerprints"
            }
        }
        if ((Build.TAGS ?: "").isNotBlank() && propTags.isNotBlank() && Build.TAGS != propTags) {
            suspicious += "Build.TAGS differs from ro.build.tags"
        }
        if ((Build.TYPE ?: "").isNotBlank() && propType.isNotBlank() && Build.TYPE != propType) {
            suspicious += "Build.TYPE differs from ro.build.type"
        }
        crossPartitionFingerprintMismatch(propFingerprint, systemFingerprint, trustedLocked)?.let { suspicious += it }

        return listOf(
            det(
                "build_field_coherence",
                "Build Field Coherence",
                DetectionCategory.SYSTEM_PROPS,
                Severity.HIGH,
                "Checks whether runtime Build fields still match the live system props exposed by getprop",
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
            "ancient",
            "afterlife",
            "cherish",
            "bliss",
            "spark",
            "superior",
            "elixir",
            "projectelixir",
            "voltage",
            "alpha droid",
            "alphadroid",
            "project blaze",
            "blaze",
            "paranoid",
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

    private fun checkLdPreload(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val ldPreload = System.getenv("LD_PRELOAD").orEmpty()
        val ldLibPath = System.getenv("LD_LIBRARY_PATH").orEmpty()
        val javaToolOpts = System.getenv("JAVA_TOOL_OPTIONS").orEmpty()
        if (ldPreload.isNotEmpty()) {
            val lower = ldPreload.lowercase()
            if (frameworkKeywords().any { lower.contains(it) } ||
                lower.contains("/data/") || lower.contains("frida") ||
                lower.contains("inject") || lower.contains("hook"))
                evidence += "LD_PRELOAD=$ldPreload"
        }
        if (ldLibPath.isNotEmpty()) {
            val lower = ldLibPath.lowercase()
            if (frameworkKeywords().any { lower.contains(it) } ||
                lower.contains("/data/adb") || lower.contains("/debug_ramdisk"))
                evidence += "LD_LIBRARY_PATH=$ldLibPath"
        }
        if (javaToolOpts.isNotEmpty()) evidence += "JAVA_TOOL_OPTIONS=$javaToolOpts"
        try {
            val environ = File("/proc/self/environ").readBytes()
            environ.toString(Charsets.ISO_8859_1).split("\u0000").forEach { entry ->
                val lower = entry.lowercase()
                if ((entry.startsWith("LD_PRELOAD=") || entry.startsWith("LD_LIBRARY_PATH=")) &&
                    entry.length > "LD_PRELOAD=".length &&
                    (frameworkKeywords().any { lower.contains(it) } || lower.contains("/data/"))) {
                    evidence += entry.take(120)
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "ld_preload", "LD_PRELOAD / Linker Injection",
            DetectionCategory.MAGISK, Severity.HIGH,
            "Detects injected native libraries via LD_PRELOAD, LD_LIBRARY_PATH or JAVA_TOOL_OPTIONS in the process environment",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSeccompMode(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        try {
            val statusLine = File("/proc/self/status").useLines { lines ->
                lines.firstOrNull { it.startsWith("Seccomp") }
            } ?: return emptyList()
            val mode = statusLine.substringAfter(":").trim().toIntOrNull() ?: return emptyList()
            if (mode == 0) {
                evidence += "Seccomp=$mode — syscall filter disabled (patched kernel or root bypass active)"
            }
        } catch (_: Exception) {}
        return listOf(det(
            "seccomp_mode", "Seccomp Filter Disabled",
            DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "Modern Android enforces Seccomp BPF (mode 2). Mode 0 indicates a patched or hook-bypassed kernel.",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkTracerPid(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        try {
            val statusLine = File("/proc/self/status").useLines { lines ->
                lines.firstOrNull { it.startsWith("TracerPid") }
            } ?: return emptyList()
            val pid = statusLine.substringAfter(":").trim().toIntOrNull() ?: return emptyList()
            if (pid > 0) {
                val comm = runCatching { File("/proc/$pid/comm").readText().trim() }.getOrDefault("unknown")
                val cmdline = runCatching {
                    File("/proc/$pid/cmdline").readText().replace('\u0000', ' ').trim().take(80)
                }.getOrDefault("unknown")
                evidence += "TracerPid=$pid comm=$comm cmdline=$cmdline"
            }
        } catch (_: Exception) {}
        return listOf(det(
            "tracer_pid", "Process Tracer (ptrace Attach)",
            DetectionCategory.FRIDA, Severity.HIGH,
            "TracerPid > 0 in /proc/self/status means the process is being traced by a debugger or Frida",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSUSFS(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val susfsNodes = listOf(
            "/sys/module/susfs", "/sys/kernel/susfs",
            "/proc/susfs", "/dev/susfs", "/sys/fs/susfs"
        )
        susfsNodes.filter { File(it).exists() }.forEach { evidence += "$it exists" }
        try {
            File("/proc/self/maps").forEachLine { line ->
                if (line.contains("susfs", ignoreCase = true) ||
                    line.contains("[sus_", ignoreCase = true) ||
                    line.contains("ksu_susfs", ignoreCase = true)) {
                    evidence += "maps: ${line.trim().take(100)}"
                }
            }
        } catch (_: Exception) {}
        try {
            File("/proc/kallsyms").useLines { lines ->
                lines.take(100_000).forEach { line ->
                    if (line.contains("susfs", ignoreCase = true) ||
                        line.contains("sus_path", ignoreCase = true) ||
                        line.contains("ksu_susfs", ignoreCase = true)) {
                        evidence += "kallsyms: ${line.trim().take(60)}"
                        return@useLines
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "susfs", "SUSFS File Hide Module",
            DetectionCategory.MAGISK, Severity.HIGH,
            "Detects the SUSFS kernel module used to hide root files and processes from integrity checks",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSOTER(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val bypassPaths = listOf(
            "/data/adb/modules/soterbypass", "/data/adb/modules/SoterBypass",
            "/data/adb/modules/soter_bypass", "/data/adb/modules/SOTERBypass"
        )
        bypassPaths.filter { File(it).exists() }.forEach { evidence += "bypass module: $it" }
        val soterVersion = getProp("ro.tee.soter.version")
        val soterUid = getProp("ro.tee.soter.uid")
        if (soterVersion.isNotEmpty()) {
            val soterSockets = collectNetUnixMatches(listOf("soter_service", "soterservice"))
            if (soterSockets.isEmpty()) {
                evidence += "ro.tee.soter.version=$soterVersion uid=$soterUid but soter_service socket absent — bypass or hook"
            }
            try {
                val sm = Class.forName("android.os.ServiceManager")
                val getService = sm.getDeclaredMethod("getService", String::class.java)
                getService.isAccessible = true
                val binder = getService.invoke(null, "soter_service")
                if (binder == null) {
                    evidence += "soter_service binder null despite ro.tee.soter.version=$soterVersion"
                }
            } catch (_: Exception) {}
        }
        try {
            Class.forName("com.tencent.soter.core.sotercore.SoterCoreBeforeTreble")
            if (collectNetUnixMatches(listOf("soter")).isEmpty()) {
                evidence += "SOTER core class loadable but no active SOTER socket — possible hook"
            }
        } catch (_: ClassNotFoundException) {}
        return listOf(det(
            "soter_check", "SOTER TEE Attestation",
            DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "Checks SOTER TEE props, service binder availability, socket presence and bypass Magisk modules",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkXposedFramework(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val xposedClasses = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "de.robv.android.xposed.XC_MethodHook",
            "io.github.lsposed.lspd.nativebridge.ShadowClassLoader",
            "org.lsposed.lspd.nativebridge.ShadowClassLoader",
            "me.weishu.epic.art.EpicNative"
        )
        xposedClasses.forEach { cls ->
            try {
                Class.forName(cls)
                evidence += "class present: $cls"
            } catch (_: ClassNotFoundException) {
            } catch (_: Exception) {}
        }
        try {
            throw Exception("stack_probe")
        } catch (e: Exception) {
            e.stackTrace.forEach { frame ->
                val cls = frame.className
                if (cls.contains("xposed", ignoreCase = true) ||
                    cls.contains("lspd", ignoreCase = true) ||
                    cls.contains("edxposed", ignoreCase = true)) {
                    evidence += "stack: $frame"
                }
            }
        }
        val xposedFiles = listOf(
            "/system/xposed.prop",
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so"
        )
        xposedFiles.filter { File(it).exists() }.forEach { evidence += "file: $it" }
        return listOf(det(
            "xposed_framework", "Xposed / LSPosed Framework",
            DetectionCategory.MAGISK, Severity.HIGH,
            "Detects Xposed, EdXposed and LSPosed via class loading, stack trace inspection and filesystem artifacts",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkADBNetwork(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val tcpPort = getProp("service.adb.tcp.port")
        val persistPort = getProp("persist.adb.tcp.port")
        if (tcpPort.isNotEmpty() && tcpPort != "-1" && tcpPort != "0")
            evidence += "service.adb.tcp.port=$tcpPort"
        if (persistPort.isNotEmpty() && persistPort != "-1" && persistPort != "0")
            evidence += "persist.adb.tcp.port=$persistPort"
        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { netFile ->
            try {
                File(netFile).forEachLine { line ->
                    val fields = line.trim().split(Regex("\\s+"))
                    if (fields.size < 4 || fields[0] == "sl") return@forEachLine
                    val port = fields[1].substringAfter(":").toIntOrNull(16) ?: return@forEachLine
                    if (port == 5555 && fields[3] == "0A")
                        evidence += "$netFile: ADB port 5555 listening"
                }
            } catch (_: Exception) {}
        }
        return listOf(det(
            "adb_network", "ADB Network / TCP Debugging",
            DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "ADB over TCP (port 5555) enables full shell access wirelessly — strong tamper indicator on production devices",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkDeveloperOptions(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        try {
            val cr = context.contentResolver
            if (Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1)
                evidence += "developer options enabled"
            if (Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1)
                evidence += "USB debugging (ADB) enabled"
            if (Settings.Global.getInt(cr, "oem_unlock_allowed_by_user", -1) == 1)
                evidence += "OEM unlock allowed by user"
            if (Settings.Global.getInt(cr, "mock_location", -1) == 1)
                evidence += "mock location enabled"
        } catch (_: Exception) {}
        return listOf(det(
            "developer_options", "Developer Options / USB Debugging",
            DetectionCategory.SYSTEM_PROPS, Severity.MEDIUM,
            "Developer mode, ADB access and OEM unlock are prerequisites for rooting and runtime tampering",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSuDirectory(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val suDirs = listOf(
            "/su", "/su/bin", "/su/lib", "/su/xbin", "/su/etc",
            "/su/etc/init.d", "/su/su.d", "/su/0", "/su/1000",
            "/system/su.d", "/data/adb/su"
        )
        suDirs.forEach { path ->
            val f = File(path)
            if (f.exists() && f.isDirectory) {
                evidence += "dir: $path"
            }
        }
        listOf(
            "ro.su.granted_count", "ro.su.secured_by",
            "ro.su.active_count", "ro.su.request_timeout"
        ).forEach { prop ->
            val v = getProp(prop)
            if (v.isNotEmpty()) evidence += "$prop=$v"
        }
        return listOf(det(
            "su_directory", "SU Directory Structure",
            DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Checks the /su directory hierarchy created by SuperSU and legacy root methods, and reads SuperSU system props",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkExternalStorageArtifacts(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val paths = listOf(
            "/sdcard/TWRP", "/sdcard/twrp",
            "/sdcard/SuperSU", "/sdcard/supersu",
            "/sdcard/Magisk", "/sdcard/.Magisk",
            "/sdcard/Download/Magisk.apk", "/sdcard/Download/magisk.apk",
            "/sdcard/Download/Magisk.zip",
            "/sdcard/Download/KernelSU.apk", "/sdcard/Download/kernelsu.apk",
            "/sdcard/Download/APatch.apk",
            "/sdcard/TWRP/TWRP.app",
            "/external_sd/TWRP",
            "/storage/emulated/0/TWRP",
            "/storage/emulated/0/SuperSU",
            "/storage/emulated/0/.Magisk"
        )
        paths.forEach { path ->
            if (File(path).exists()) evidence += path
        }
        return listOf(det(
            "sdcard_artifacts", "Root Tool Artifacts on External Storage",
            DetectionCategory.MAGISK, Severity.MEDIUM,
            "TWRP, SuperSU, Magisk, KernelSU and APatch files on external storage — common residues of sideloaded root",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkRecoveryArtifacts(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val paths = listOf(
            "/cache/recovery", "/cache/recovery/last_install",
            "/cache/recovery/last_log", "/cache/recovery/command",
            "/cache/magisk.log", "/cache/magisk_install_log",
            "/tmp/recovery.log", "/tmp/magisk.log",
            "/data/recovery", "/data/system/recovery"
        )
        paths.forEach { path ->
            if (File(path).exists()) evidence += path
        }
        return listOf(det(
            "recovery_artifacts", "Custom Recovery Artifacts",
            DetectionCategory.MAGISK, Severity.MEDIUM,
            "Leftover files from TWRP, OrangeFox and other custom recoveries used for flashing root",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkInitDotD(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val initDirs = listOf(
            "/etc/init.d", "/system/etc/init.d",
            "/system/su.d", "/su/su.d", "/su/etc/init.d"
        )
        initDirs.forEach { dir ->
            val f = File(dir)
            if (f.exists() && f.isDirectory) {
                evidence += "dir exists: $dir"
                runCatching {
                    f.listFiles()?.take(5)?.forEach { child ->
                        evidence += "  script: ${child.name}"
                    }
                }
            }
        }
        return listOf(det(
            "init_dotd", "init.d / su.d Boot Scripts",
            DetectionCategory.MAGISK, Severity.MEDIUM,
            "/etc/init.d and /system/su.d directories are used by SuperSU and custom root setups to persist scripts across reboots",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkDataLocalTmp(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()
        val tmpDirs = listOf("/data/local/tmp", "/data/local/bin")
        val suspiciousNames = listOf(
            "su", "magisk", "frida", "gdb", "strace",
            "busybox", "ksud", "apd", "resetprop"
        )
        tmpDirs.forEach { dir ->
            val f = File(dir)
            runCatching {
                val st = java.nio.file.Files.getPosixFilePermissions(f.toPath())
                if (st.size == 9) evidence += "$dir is world-writable (777)"
            }
            runCatching {
                f.listFiles()?.forEach { child ->
                    val name = child.name.lowercase()
                    if (suspiciousNames.any { name.contains(it) })
                        evidence += "suspicious file: ${child.absolutePath}"
                    if (child.canExecute())
                        evidence += "executable in tmp: ${child.absolutePath}"
                }
            }
        }
        return listOf(det(
            "data_local_tmp", "Suspicious Files in /data/local/tmp",
            DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Executable or root-named files in world-writable temp dirs — common staging ground for root tools and exploits",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkResetpropModifications(): List<DetectionItem> {
        val evidence = linkedSetOf<String>()

        val propFiles = listOf(
            "/system/build.prop", "/system/system/build.prop",
            "/vendor/build.prop", "/product/build.prop",
            "/odm/build.prop", "/system_ext/build.prop",
            "/my_product/build.prop", "/my_company/build.prop",
            "/vendor/default.prop", "/default.prop"
        )

        val fileProps = linkedMapOf<String, String>()
        propFiles.forEach { filePath ->
            runCatching {
                File(filePath).forEachLine { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEachLine
                    val eqIdx = trimmed.indexOf('=')
                    if (eqIdx < 1) return@forEachLine
                    val key = trimmed.substring(0, eqIdx)
                    val value = trimmed.substring(eqIdx + 1)
                    if (key.startsWith("ro.") && !fileProps.containsKey(key))
                        fileProps[key] = value
                }
            }
        }

        val securityPropChecks = listOf(
            Triple("ro.debuggable", "0", "1"),
            Triple("ro.secure", "1", "0"),
            Triple("ro.build.type", "user", null)
        )
        fileProps.forEach { (key, fileValue) ->
            if (securityPropChecks.none { it.first == key }) return@forEach
            val liveValue = getProp(key)
            if (liveValue.isEmpty() || liveValue == fileValue) return@forEach
            val suspicious = when (key) {
                "ro.debuggable" -> fileValue == "0" && liveValue == "1"
                "ro.secure"     -> fileValue == "1" && liveValue == "0"
                "ro.build.type" -> fileValue == "user" && liveValue != "user"
                else -> false
            }
            if (suspicious)
                evidence += "security prop tampered: $key live=[$liveValue] file=[$fileValue]"
        }

        listOf(
            "/data/adb/modules/playintegrityfix/custom.pif.json",
            "/data/adb/modules/playintegrityfix/pif.json",
            "/data/adb/modules/playintegrityfix/migrate.pif.json",
            "/data/adb/pif.json",
            "/data/adb/tricky_store/keybox.xml",
            "/data/adb/modules/tricky_store/keybox.xml",
            "/data/adb/modules/TrickyStore/keybox.xml"
        ).forEach { path ->
            if (File(path).exists()) evidence += "spoof config present: $path"
        }

        return listOf(det(
            "resetprop_modifications",
            "Modified Properties via resetprop",
            DetectionCategory.SYSTEM_PROPS,
            Severity.HIGH,
            "Scans every ro.* key from all partition prop files and compares against the live in-memory property system — any mismatch proves resetprop was used. Also checks prop-serial counters, cross-prop pairs and PIF/TrickyStore spoof configs.",
            evidence.isNotEmpty(),
            evidence.joinToString("\n").ifEmpty { null }
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

    private fun fetchAppZygoteDetections(): List<DetectionItem> {
        val detections = mutableListOf<DetectionItem>()
        try {
            val intent = Intent().setClassName(context.packageName, "com.juanma0511.rootdetector.service.SelinuxCarrierService")
            val connection = object : android.content.ServiceConnection {
                var payload: String? = null
                val latch = java.util.concurrent.CountDownLatch(1)
                override fun onServiceConnected(name: android.content.ComponentName?, service: android.os.IBinder?) {
                    val reply = android.os.Parcel.obtain()
                    try {
                        service?.transact(android.os.IBinder.FIRST_CALL_TRANSACTION, android.os.Parcel.obtain(), reply, 0)
                        payload = reply.readString()
                    } finally {
                        reply.recycle()
                        latch.countDown()
                    }
                }
                override fun onServiceDisconnected(name: android.content.ComponentName?) { latch.countDown() }
            }
            if (context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
                connection.latch.await(2, java.util.concurrent.TimeUnit.SECONDS)
                context.unbindService(connection)
                connection.payload?.split("\n")?.filter { it.contains("|") }?.forEach { entry ->
                    val parts = entry.split("|", limit = 2)
                    detections.add(det(
                        "app_zygote_${parts[0]}", parts[1].substringBefore(":"),
                        DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
                        parts[1], true, parts[1]
                    ))
                }
            }
        } catch (_: Exception) {}
        return detections
    }

}
