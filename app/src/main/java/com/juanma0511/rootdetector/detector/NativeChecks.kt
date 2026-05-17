package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity

class NativeChecks {

    companion object {
        private var libLoaded = false
        private var libError: String? = null

        init {
            try {
                System.loadLibrary("rootdetector")
                libLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                libError = e.message
            }
        }

        fun isAvailable() = libLoaded
        fun loadError() = libError
    }

    external fun runNativeChecks(): Array<String>

    fun run(): List<DetectionItem> {
        if (!libLoaded) return emptyList()

        return try {
            val raw = runNativeChecks()
            raw.mapNotNull { entry ->
                val idx = entry.indexOf('|')
                if (idx < 0) return@mapNotNull null
                val name = entry.substring(0, idx)
                val desc = entry.substring(idx + 1)

                DetectionItem(
                    id = "native_${name.lowercase().replace(" ", "_").take(30)}",
                    name = name,
                    description = desc,
                    category = classifyCategory(name),
                    severity = classifySeverity(name),
                    detected = true,
                    detail = desc
                )
            }
        } catch (e: Exception) {
            listOf(
                DetectionItem(
                    id = "native_error",
                    name = "Native checks error",
                    description = e.message ?: "Unknown native error",
                    category = DetectionCategory.MAGISK,
                    severity = Severity.LOW,
                    detected = false,
                    detail = e.message
                )
            )
        }
    }

    private fun classifyCategory(name: String): DetectionCategory = when {
        name.contains("Frida", ignoreCase = true) ||
        name.contains("Port", ignoreCase = true)            -> DetectionCategory.FRIDA
        name.contains("Magisk", ignoreCase = true) ||
        name.contains("Zygisk", ignoreCase = true) ||
        name.contains("Socket", ignoreCase = true) ||
        name.contains("Mount", ignoreCase = true) ||
        name.contains("Cgroup", ignoreCase = true) ||
        name.contains("Hidden Process", ignoreCase = true)  -> DetectionCategory.MAGISK
        name.contains("KernelSU", ignoreCase = true) ||
        name.contains("KSU", ignoreCase = true) ||
        name.contains("APatch", ignoreCase = true) ||
        name.contains("jbd2", ignoreCase = true)            -> DetectionCategory.MAGISK
        name.contains("SU", ignoreCase = true) ||
        name.contains("Root File", ignoreCase = true) ||
        name.contains("Root Binar", ignoreCase = true) ||
        name.contains("Root Process", ignoreCase = true) ||
        name.contains("Root Daemon", ignoreCase = true)     -> DetectionCategory.SU_BINARIES
        name.contains("Prop", ignoreCase = true) ||
        name.contains("resetprop", ignoreCase = true) ||
        name.contains("SELinux", ignoreCase = true) ||
        name.contains("Kernel", ignoreCase = true) ||
        name.contains("AVB", ignoreCase = true) ||
        name.contains("Bootloader", ignoreCase = true) ||
        name.contains("dm-verity", ignoreCase = true)       -> DetectionCategory.SYSTEM_PROPS
        name.contains("Custom ROM", ignoreCase = true) ||
        name.contains("LineageOS", ignoreCase = true) ||
        name.contains("ROM", ignoreCase = true)             -> DetectionCategory.CUSTOM_ROM
        name.contains("Injected", ignoreCase = true) ||
        name.contains("RWX", ignoreCase = true) ||
        name.contains("Hook", ignoreCase = true) ||
        name.contains("Bridge", ignoreCase = true) ||
        name.contains("Trace", ignoreCase = true) ||
        name.contains("PTY", ignoreCase = true) ||
        name.contains("Env", ignoreCase = true)             -> DetectionCategory.MAGISK
        else                                                 -> DetectionCategory.MAGISK
    }

    private fun classifySeverity(name: String): Severity = when {
        name.contains("prctl", ignoreCase = true) ||
        name.contains("kill 0x", ignoreCase = true) ||
        name.contains("SU Exec", ignoreCase = true) ||
        name.contains("Magisk Socket", ignoreCase = true) ||
        name.contains("Mount Loophole", ignoreCase = true) ||
        name.contains("resetprop", ignoreCase = true) ||
        name.contains("Frida", ignoreCase = true) ||
        name.contains("uid=0", ignoreCase = true)           -> Severity.HIGH
        name.contains("Custom ROM", ignoreCase = true) ||
        name.contains("Bootloader", ignoreCase = true) ||
        name.contains("PTY", ignoreCase = true)             -> Severity.MEDIUM
        else                                                 -> Severity.HIGH
    }
}
