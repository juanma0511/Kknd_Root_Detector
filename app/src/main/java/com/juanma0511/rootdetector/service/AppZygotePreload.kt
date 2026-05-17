package com.juanma0511.rootdetector.service

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.os.Build
import android.system.Os
import com.juanma0511.rootdetector.detector.NativeChecks
import java.lang.reflect.Method

class AppZygotePreload : ZygotePreload {

    override fun doPreload(appInfo: ApplicationInfo) {
        val payload = runCatching {
            val currentUid = Os.getuid()
            if (currentUid != appInfo.uid) {
                "UID_MISMATCH"
            } else {
                val nativeResults = if (NativeChecks.isAvailable()) {
                    NativeChecks().runNativeChecks().toList()
                } else {
                    emptyList()
                }
                val javaResults = runJavaSelinuxChecks()
                (nativeResults + javaResults).distinct().joinToString("\n")
            }
        }.getOrElse { it.message ?: "ERROR" }

        SelinuxCarrierService.setPreloadedPayload(payload)
    }

    private fun runJavaSelinuxChecks(): List<String> {
        val results = mutableListOf<String>()
        val checkAccess: (String, String, String, String) -> Boolean? = { scon, tcon, tclass, perm ->
            runCatching {
                val cls = Class.forName("android.os.SELinux")
                val method = cls.getMethod("checkSELinuxAccess", String::class.java, String::class.java, String::class.java, String::class.java)
                method.invoke(null, scon, tcon, tclass, perm) as? Boolean
            }.getOrNull()
        }

        val rules = listOf(
            Triple("u:r:system_server:s0", "u:r:system_server:s0", "process" to "execmem"),
            Triple("u:r:untrusted_app:s0", "u:object_r:magisk_file:s0", "file" to "read"),
            Triple("u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file" to "read"),
            Triple("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file" to "read"),
            Triple("u:r:adbd:s0", "u:r:adbroot:s0", "binder" to "call")
        )

        rules.forEach { (src, tgt, pair) ->
            val (cls, perm) = pair
            if (checkAccess(src, tgt, cls, perm) == true) {
                results.add("selinux_dirty_policy_java|Java DirtySepolicy: $src -> $tgt ($perm)")
            }
        }
        return results
    }
}
