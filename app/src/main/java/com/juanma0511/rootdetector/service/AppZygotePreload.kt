package com.juanma0511.rootdetector.service

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.os.Build
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.juanma0511.rootdetector.detector.NativeChecks
import java.io.File
import java.nio.charset.StandardCharsets
import java.lang.reflect.Method

class AppZygotePreload : ZygotePreload {

    override fun doPreload(appInfo: ApplicationInfo) {
        val uid = Os.getuid()
        if (uid != appInfo.uid) {
            SelinuxCarrierService.setPreloadedPayload("ERROR: UID mismatch: $uid != app uid ${appInfo.uid}")
            return
        }

        val fileSet = HashSet<String>()
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
            File("/proc/self/fd").listFiles()?.forEach { fileSet.add(it.name) }
        }

        val payload = runCatching {
            doCheck()
        }.getOrElse { "ERROR: ${it.message}" }

        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
            File("/proc/self/fd").listFiles()?.forEach {
                if (fileSet.add(it.name)) {
                    runCatching { Os.dup2(java.io.FileDescriptor.`in`, it.name.toInt()) }
                }
            }
        }

        SelinuxCarrierService.setPreloadedPayload(payload)
    }

    private fun doCheck(): String {
        val selinuxClass = runCatching { Class.forName("android.os.SELinux") }.getOrNull() ?: return "ERROR: SELinux class not found"

        val isEnabled = runCatching { selinuxClass.getMethod("isSELinuxEnabled").invoke(null) as Boolean }.getOrDefault(false)
        if (!isEnabled) return "ERROR: SELinux is disabled"

        val context = runCatching { selinuxClass.getMethod("getContext").invoke(null) as String }.getOrNull()
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) return "ERROR: unexpected SELinux context: $context"

        val pidContext = runCatching { selinuxClass.getMethod("getPidContext", Int::class.javaPrimitiveType).invoke(null, Os.getpid()) as String }.getOrNull()
        if (context != pidContext) return "ERROR: PID context mismatch: $pidContext"

        val procContext = runCatching { selinuxClass.getMethod("getFileContext", String::class.java).invoke(null, "/proc/self") as String }.getOrNull()
        if (context != procContext) return "ERROR: /proc/self context mismatch: $procContext"

        val isEnforced = runCatching { selinuxClass.getMethod("isSELinuxEnforced").invoke(null) as Boolean }.getOrDefault(false)
        if (!isEnforced) return "ERROR: SELinux is permissive"

        val checkAccessMethod = selinuxClass.getMethod("checkSELinuxAccess", String::class.java, String::class.java, String::class.java, String::class.java)
        fun checkAccess(scon: String, tcon: String, tclass: String, perm: String): Boolean {
            return runCatching { checkAccessMethod.invoke(null, scon, tcon, tclass, perm) as Boolean }.getOrDefault(false)
        }


        val sb = StringBuilder()
        fun contextExists(ctx: String): Boolean {
            val data = ctx.toByteArray(StandardCharsets.UTF_8)
            try {
                java.io.FileOutputStream("/sys/fs/selinux/context").use { out ->
                    Os.write(out.fd, data, 0, data.size)
                }
                return true
            } catch (e: Exception) {
                if (e is ErrnoException) {
                    if (e.errno != OsConstants.EINVAL) return true
                }
            }
            if (checkAccess("u:r:app_zygote:s0", ctx, "process", "dyntransition")) return true
            try {
                java.io.FileOutputStream("/proc/self/attr/current").use { out ->
                    Os.write(out.fd, data, 0, data.size)
                }
                return true
            } catch (e: Exception) {
                if (e is ErrnoException) {
                    if (e.errno == OsConstants.EPERM) return true
                }
            }
            return false
        }

        if (checkAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) sb.append("system_server can execmem; ")
        if (Build.TYPE == "user" && checkAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) sb.append("found AOSP su in user build; ")

        if (contextExists("u:r:adbroot:s0") || checkAccess("u:r:adbd:s0", "u:r:adbroot:s0", "binder", "call")) sb.append("found adb_root; ")

        if (contextExists("u:r:magisk:s0") || contextExists("u:object_r:magisk_file:s0") ||
            checkAccess("u:r:untrusted_app:s0", "u:object_r:magisk_file:s0", "file", "read") ||
            checkAccess("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate") ||
            checkAccess("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) sb.append("found Magisk; ")

        val ksuDomain = contextExists("u:r:ksu:s0")
        val ksuFile = contextExists("u:object_r:ksu_file:s0")
        if (ksuDomain || ksuFile ||
            checkAccess("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read") ||
            checkAccess("u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file", "read")) {
            val bp = (if (ksuDomain) "1" else "0") + (if (ksuFile) "1" else "0")
            sb.append("found KernelSU (bitpair $bp); ")
        }

        if (contextExists("u:object_r:lsposed_file:s0") ||
            checkAccess("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read") ||
            checkAccess("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")) sb.append("found LSPosed; ")

        if (contextExists("u:object_r:xposed_data:s0") || contextExists("u:object_r:xposed_file:s0") ||
            checkAccess("u:r:untrusted_app:s0", "u:object_r:xposed_data:s0", "file", "read") ||
            checkAccess("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) sb.append("found Xposed; ")

        if (checkAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) sb.append("found ZygiskNext; ")

        val nativeResults = if (NativeChecks.isAvailable()) NativeChecks().runNativeChecks() else emptyArray()
        val nativeString = nativeResults.joinToString("\n")

        return if (sb.isEmpty()) "OK|No dirty sepolicy found\n$nativeString" else "WARNING|$sb\n$nativeString"
    }
}
