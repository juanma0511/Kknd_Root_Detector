package com.juanma0511.rootdetector.detector

data class PropValueCheck(
    val key: String,
    val suspiciousValues: Set<String>
)

object GetPropCatalog {
    val dangerousRootProps = listOf(
        PropValueCheck("ro.debuggable", setOf("1")),
        PropValueCheck("ro.secure", setOf("0")),
        PropValueCheck("ro.build.type", setOf("userdebug", "eng")),
        PropValueCheck("service.adb.root", setOf("1")),
        PropValueCheck("ro.allow.mock.location", setOf("1")),
        PropValueCheck("persist.sys.root_access", setOf("1", "3")),
        PropValueCheck("ro.boot.veritymode", setOf("disabled", "logging")),
        PropValueCheck("ro.boot.flash.locked", setOf("0")),
        PropValueCheck("ro.boot.vbmeta.device_state", setOf("unlocked")),
        PropValueCheck("ro.boot.verifiedbootstate", setOf("orange", "yellow"))
    )

    val spoofedBootProps = listOf(
        PropValueCheck("ro.boot.vbmeta.device_state", setOf("unlocked")),
        PropValueCheck("ro.boot.verifiedbootstate", setOf("orange", "yellow")),
        PropValueCheck("ro.boot.flash.locked", setOf("0")),
        PropValueCheck("ro.boot.veritymode", setOf("disabled", "logging")),
        PropValueCheck("ro.boot.warranty_bit", setOf("1"))
    )

    val kernelSuProps = listOf(
        "ro.boot.kernelsu.version",
        "sys.kernelsu.version",
        "ro.kernelsu.version",
        "ro.boot.ksu.version",
        "ro.ksunext.version",
        "ro.boot.ksunext.version"
    )

    val NLSoundProps = listOf(
        "ro.audio.ignore_effects",
        "persist.bluetooth.sbc_hd_higher_bitrate",
        "persist.bt.sbc_hd_enabled"
    )

    fun collectMatches(getProp: (String) -> String, checks: List<PropValueCheck>): List<String> {
        return checks.mapNotNull { check ->
            val value = getProp(check.key).lowercase()
            if (value.isNotEmpty() && check.suspiciousValues.any { value == it || value.contains(it) }) {
                "${check.key}=$value"
            } else {
                null
            }
        }
    }
}
