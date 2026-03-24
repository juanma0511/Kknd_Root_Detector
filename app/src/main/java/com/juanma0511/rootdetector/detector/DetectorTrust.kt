package com.juanma0511.rootdetector.detector

import java.io.File
import java.util.concurrent.TimeUnit

object DetectorTrust {

    private val directSystemMounts = HardcodedSignals.directSystemMounts.toSet()

    private val stockVendorMountMarkers = HardcodedSignals.stockVendorMountMarkers

    private val rootKeywords = HardcodedSignals.rootKeywords

    private val rootPaths = HardcodedSignals.rootPaths

    fun frameworkKeywords(): List<String> = rootKeywords

    fun isOplusMarker(value: String): Boolean {
        val lower = value.lowercase()
        return lower.contains("oplu") || lower.contains("oplusex")
    }

    fun getProp(key: String): String = try {
        val process = Runtime.getRuntime().exec("getprop $key")
        val finished = process.waitFor(1, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            ""
        } else {
            process.inputStream.bufferedReader().readLine()?.trim().orEmpty()
        }
    } catch (_: Exception) {
        ""
    }

    fun bootLooksTrustedLocked(): Boolean {
        val flashLocked = getProp("ro.boot.flash.locked").lowercase()
        val vbmetaState = getProp("ro.boot.vbmeta.device_state").lowercase()
        val verifiedBoot = getProp("ro.boot.verifiedbootstate").lowercase()
        val verityMode = getProp("ro.boot.veritymode").lowercase()
        val vbmetaDigest = getProp("ro.boot.vbmeta.digest").lowercase()
        val bootKey = getProp("ro.boot.bootkey").lowercase()
        val locked = flashLocked == "1" || vbmetaState == "locked"
        val greenBoot = verifiedBoot == "green" || (verifiedBoot.isEmpty() && locked)
        val verityOk = verityMode.isEmpty() || verityMode == "enforcing" || verityMode == "eio"
        val digestOk = vbmetaDigest.isEmpty() || vbmetaDigest == "unknown" || !isZeroLike(vbmetaDigest)
        val bootKeyOk = bootKey.isEmpty() || bootKey == "unknown" || !isZeroLike(bootKey)
        return locked && greenBoot && verityOk && digestOk && bootKeyOk && !hasExplicitRootArtifacts()
    }

    fun shouldTrackSensitiveMount(mountPoint: String): Boolean {
        return mountPoint in directSystemMounts ||
            mountPoint == "/debug_ramdisk" ||
            mountPoint.startsWith("/.magisk") ||
            mountPoint.startsWith("/data/adb")
    }

    fun isDirectSystemMount(mountPoint: String): Boolean = mountPoint in directSystemMounts

    fun hasExplicitMountRootMarker(value: String): Boolean {
        val lower = value.lowercase()
        if (isOplusMarker(lower)) return false
        if (rootPaths.any { lower.contains(it) }) return true
        val exactMarkers = setOf(
            "magisk", "zygisk", "magiskd", "ksu", "ksud", "kernelsu",
            "apatch", "shamiko", "trickystore", "tricky_store", "susfs", "resetprop"
        )
        if (exactMarkers.any {
                Regex("""(^|[^a-z0-9_])${Regex.escape(it)}([^a-z0-9_]|$)""").containsMatchIn(lower)
            }) {
            return true
        }
        return lower.contains("/data/adb") ||
            lower.contains("/.magisk") ||
            lower.contains("/dev/magisk") ||
            lower.contains("/sbin/.magisk") ||
            lower.contains("upperdir=/data/") ||
            lower.contains("workdir=/data/") ||
            lower.contains("upperdir=/debug_ramdisk") ||
            lower.contains("workdir=/debug_ramdisk")
    }

    fun isLikelyStockVendorMount(signature: String, mountPoint: String): Boolean {
        if (!isDirectSystemMount(mountPoint)) return false
        val lower = ("$mountPoint $signature").lowercase()
        if (rootPaths.any { lower.contains(it) } || rootKeywords.any { lower.contains(it) }) return false
        if (stockVendorMountMarkers.any { lower.contains(it) }) return true
        return Regex("""(^|[^a-z])my_[a-z0-9_]+""").containsMatchIn(lower)
    }

    fun hasRootMountSignal(signature: String, mountPoint: String, trustedLocked: Boolean): Boolean {
        val lower = ("$mountPoint $signature").lowercase()
        if (isOplusMarker(lower)) return false
        if (trustedLocked && isLikelyStockVendorMount(signature, mountPoint)) return false
        val keywordHit = hasExplicitMountRootMarker(lower)
        if (keywordHit) return true
        val systemPartition = isDirectSystemMount(mountPoint)
        val mountAbuse = systemPartition &&
            (lower.contains("overlay") || lower.contains("tmpfs") || lower.contains("loop")) &&
            (
                lower.contains("upperdir=/data/") ||
                    lower.contains("workdir=/data/") ||
                    lower.contains("/debug_ramdisk") ||
                    lower.contains("/data/adb") ||
                    lower.contains("/.magisk")
                )
        return mountAbuse && !trustedLocked
    }

    fun isSuspiciousDeletedOrMemfdMap(line: String, trustedLocked: Boolean): Boolean {
        val lower = line.lowercase()
        val ignoredMarkers = HardcodedSignals.ignoredMemfdMarkers
        if (ignoredMarkers.any { lower.contains(it) }) return false
        val rootKeywordHit = rootKeywords.any { lower.contains(it) }
        val rootPathHit = rootPaths.any { lower.contains(it) }
        val deletedHit = lower.contains("(deleted)") && (rootKeywordHit || rootPathHit)
        val memfdExec = lower.contains("memfd:") && (line.contains("r-xp") || line.contains("rwxp") || line.contains("r-xs"))
        if (deletedHit) return true
        if (memfdExec && (rootKeywordHit || rootPathHit)) return true
        return memfdExec && !trustedLocked && lower.contains("frida")
    }

    fun isLikelyRuntimeInjectionEvidence(value: String, trustedLocked: Boolean): Boolean {
        val lower = value.lowercase()
        val strongKeywords = HardcodedSignals.strongRuntimeKeywords
        if (strongKeywords.any { lower.contains(it) }) return true
        val genericHook = HardcodedSignals.genericHookKeywords.any { lower.contains(it) }
        if (!genericHook) return false
        val rootedContext = rootPaths.any { lower.contains(it) } || lower.contains("memfd:") || lower.contains("(deleted)")
        return rootedContext && !trustedLocked
    }

    private fun hasExplicitRootArtifacts(): Boolean {
        if (rootPaths.any { path -> File(path).exists() }) return true

        val moduleDirs = HardcodedSignals.moduleDirs
        moduleDirs.forEach { dirPath ->
            File(dirPath).listFiles()?.forEach { module ->
                val name = module.name.lowercase()
                if (rootKeywords.any { name.contains(it) }) return true
                val propFile = File(module, "module.prop")
                if (propFile.exists()) {
                    val content = runCatching { propFile.readText().lowercase() }.getOrDefault("")
                    if (rootKeywords.any { content.contains(it) }) return true
                }
            }
        }

        var mountHit = false
        try {
            File("/proc/mounts").forEachLine { line ->
                val lower = line.lowercase()
                if (rootPaths.any { lower.contains(it) } || rootKeywords.any { lower.contains(it) }) {
                    mountHit = true
                }
            }
        } catch (_: Exception) {}
        if (mountHit) return true

        var unixHit = false
        try {
            File("/proc/net/unix").forEachLine { line ->
                val lower = line.lowercase()
                if (rootKeywords.any { lower.contains(it) }) {
                    unixHit = true
                }
            }
        } catch (_: Exception) {}
        if (unixHit) return true

        return false
    }

    private fun isZeroLike(value: String): Boolean {
        val normalized = value.filterNot { it == ':' || it == '-' || it.isWhitespace() }
        return normalized.isNotEmpty() && normalized.all { it == '0' }
    }
}
