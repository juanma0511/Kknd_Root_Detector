package com.juanma0511.rootdetector.detector

import android.content.Context
import android.content.res.Resources
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.juanma0511.rootdetector.model.CheckStatus
import com.juanma0511.rootdetector.model.HwCheckItem
import com.juanma0511.rootdetector.model.HwGroup
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.security.auth.x500.X500Principal

class KeyAttestationChecker(private val context: Context) {

    private enum class RootStatus {
        GOOGLE,
        KNOX,
        OEM,
        AOSP,
        UNKNOWN
    }

    private enum class SecurityLevel {
        SOFTWARE,
        TEE,
        STRONGBOX,
        UNKNOWN
    }

    private data class GeneratedAttestation(
        val certs: List<X509Certificate>,
        val securityLevel: SecurityLevel,
        val extensionOid: String?,
        val strategyLabel: String
    )

    private data class AttestationAttempt(
        val generated: GeneratedAttestation?,
        val errors: List<String>
    )

    private data class KeyStrategy(
        val label: String,
        val algorithm: String
    )

    private val teeAttempt by lazy { runAttestationAttempt(strongBox = false) }
    private val strongBoxAttempt by lazy {
        if (hasStrongBoxFeature()) runAttestationAttempt(strongBox = true)
        else AttestationAttempt(null, listOf("This device does not advertise a dedicated StrongBox-backed keystore"))
    }

    private val googleRootKey = decodeKey(
        """
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==
        """
    )

    private val aospEcRootKey = decodeKey(
        """
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==
        """
    )

    private val aospRsaRootKey = decodeKey(
        """
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwIDAQAB
        """
    )

    private val knoxKeys = setOf(
        decodeKey("""
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBs9Qjr//REhkXW7jUqjY9KNwWac4r5+kdUGk+TZjRo1YEa47Axwj6AJsbOjo4QsHiYRiWTELvFeiuBsKqyuF0xyAAKvDofBqrEq1/Ckxo2mz7Q4NQes3g4ahSjtgUSh0k85fYwwHjCeLyZ5kEqgHG9OpOH526FFAK3slSUgC8RObbxys=
        """),
        decodeKey("""
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd124n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBoZsapxB0gAOs0jSPRX5M=
        """),
        decodeKey("""
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9XeEN8lg6p5xvMVWG42P2Qi/aRKX2rPRNgK92UlO9O/TIFCKHC1AWCLFitPVEow5W+yEgC2wOiYxgepY85TOoH0AuEkLoiC6ldbF2uNVU3rYYSytWAJg3GFKd1l9VLDmxox58Hyw2Jmdd5VSObGiTFQ/SgKsn2fbQPtpGlNxgEfd6Y8=
        """),
    )

    fun runAllChecks(): List<HwCheckItem> {
        val items = mutableListOf<HwCheckItem>()
        items += checkKeyAttestationChain(strongBox = false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            items += checkKeyAttestationChain(strongBox = true)
        }
        items += checkRootCertTrust()
        return items
    }

    fun checkKeyAttestationChain(strongBox: Boolean): HwCheckItem {
        val label = if (strongBox) "StrongBox" else "TEE"
        val id = if (strongBox) "attest_chain_sb" else "attest_chain_tee"
        val compromisedBoot = isBootStateCompromised()

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return det(id, "Key Attestation ($label)", HwGroup.KEYSTORE, CheckStatus.WARN,
                "Key attestation requires Android 7.0+", "Android < 7.0")
        }

        if (strongBox && !hasStrongBoxFeature()) {
            return det(id, "Key Attestation ($label)", HwGroup.KEYSTORE, CheckStatus.UNKNOWN,
                "StrongBox attestation is optional and only available on supported hardware",
                "This device does not advertise a dedicated StrongBox-backed keystore")
        }

        val attempt = if (strongBox) strongBoxAttempt else teeAttempt
        val generated = attempt.generated
        if (generated == null) {
            val detail = buildFailureDetail(attempt.errors)
            val status = if (strongBox && !hasStrongBoxFeature()) CheckStatus.UNKNOWN else fallbackStatus(compromisedBoot)
            return det(id, "Key Attestation ($label)", HwGroup.KEYSTORE, status,
                "Could not complete the key attestation check", detail)
        }

        val chainError = verifyChain(generated.certs)
        if (chainError != null) {
            return det(id, "Key Attestation ($label)", HwGroup.KEYSTORE, fallbackStatus(compromisedBoot),
                "Attested keystore chain must validate from leaf to root", formatGeneratedDetail(generated, chainError))
        }

        if (generated.extensionOid == null) {
            return det(id, "Key Attestation ($label)", HwGroup.KEYSTORE, fallbackStatus(compromisedBoot),
                "No attestation extension was returned by the keystore", formatGeneratedDetail(generated, "Certificate chain present, but no attestation extension was exposed"))
        }

        val status = when {
            strongBox && generated.securityLevel == SecurityLevel.STRONGBOX -> CheckStatus.PASS
            strongBox -> CheckStatus.FAIL
            generated.securityLevel == SecurityLevel.TEE || generated.securityLevel == SecurityLevel.STRONGBOX -> CheckStatus.PASS
            generated.securityLevel == SecurityLevel.SOFTWARE && compromisedBoot -> CheckStatus.FAIL
            else -> CheckStatus.WARN
        }

        val detail = buildString {
            append(formatGeneratedDetail(generated, null))
            if (strongBox && generated.securityLevel != SecurityLevel.STRONGBOX) {
                append("\nStrongBox attestation was not exposed by this device")
            }
        }.trim()

        return det(id, "Key Attestation ($label)", HwGroup.KEYSTORE, status,
            "Generates an attested key and checks whether the returned chain exposes TEE or StrongBox attestation",
            detail)
    }

    fun checkRootCertTrust(): HwCheckItem {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return det("attest_root_trust", "Attestation Root Trust", HwGroup.KEYSTORE, CheckStatus.WARN,
                "Requires Android 7.0+", null)
        }

        val compromisedBoot = isBootStateCompromised()
        val generated = teeAttempt.generated
        if (generated == null) {
            return det("attest_root_trust", "Attestation Root Trust", HwGroup.KEYSTORE, fallbackStatus(compromisedBoot),
                "Could not verify attestation root trust", buildFailureDetail(teeAttempt.errors))
        }

        val chainError = verifyChain(generated.certs)
        if (chainError != null) {
            return det("attest_root_trust", "Attestation Root Trust", HwGroup.KEYSTORE, fallbackStatus(compromisedBoot),
                "The attestation certificate chain must verify correctly", formatGeneratedDetail(generated, chainError))
        }

        if (generated.extensionOid == null) {
            return det("attest_root_trust", "Attestation Root Trust", HwGroup.KEYSTORE, fallbackStatus(compromisedBoot),
                "No attestation extension was returned by the keystore", formatGeneratedDetail(generated, "Certificate chain present, but no attestation extension was exposed"))
        }

        val root = generated.certs.last()
        val rootStatus = identifyRoot(root)
        val status = when (rootStatus) {
            RootStatus.GOOGLE, RootStatus.KNOX, RootStatus.OEM -> CheckStatus.PASS
            RootStatus.AOSP, RootStatus.UNKNOWN -> CheckStatus.WARN
        }
        val value = when (rootStatus) {
            RootStatus.GOOGLE -> "Google"
            RootStatus.KNOX -> "Samsung Knox"
            RootStatus.OEM -> "OEM"
            RootStatus.AOSP -> "AOSP"
            RootStatus.UNKNOWN -> "Unknown"
        }

        val detail = buildString {
            append(formatGeneratedDetail(generated, null))
            append("\nTrust: $value")
            append("\nRoot CN: ${root.subjectX500Principal.name.take(96)}")
            append("\nIssuer: ${root.issuerX500Principal.name.take(96)}")
            if (rootStatus == RootStatus.UNKNOWN) {
                append("\nUnrecognized attestation root is treated as vendor-specific until proven otherwise")
            }
        }.trim()

        return det("attest_root_trust", "Attestation Root Trust", HwGroup.KEYSTORE, status,
            "Recognizes Google, Samsung Knox and OEM attestation roots using KeyAttestation-style public key matching",
            detail)
    }

    private fun runAttestationAttempt(strongBox: Boolean): AttestationAttempt {
        val errors = mutableListOf<String>()
        for (strategy in keyStrategies()) {
            val result = runCatching { generateAttestation(strongBox, strategy) }
            val generated = result.getOrNull()
            if (generated != null) {
                return AttestationAttempt(generated, errors)
            }
            val throwable = result.exceptionOrNull()
            errors += buildString {
                append(strategy.label)
                append(": ")
                append(throwable?.javaClass?.simpleName ?: "Error")
                val message = throwable?.message?.take(180)
                if (!message.isNullOrBlank()) {
                    append(": ")
                    append(message)
                }
            }
            if (strongBox && throwable is StrongBoxUnavailableException) {
                break
            }
        }
        return AttestationAttempt(null, errors)
    }

    private fun keyStrategies(): List<KeyStrategy> {
        return listOf(
            KeyStrategy("EC P-256", KeyProperties.KEY_ALGORITHM_EC),
            KeyStrategy("RSA 2048", KeyProperties.KEY_ALGORITHM_RSA)
        )
    }

    private fun generateAttestation(strongBox: Boolean, strategy: KeyStrategy): GeneratedAttestation {
        val alias = "rootdetector_attest_${if (strongBox) "sb" else "tee"}_${strategy.algorithm.lowercase()}_${System.nanoTime()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        runCatching { keyStore.deleteEntry(alias) }

        try {
            val generator = KeyPairGenerator.getInstance(strategy.algorithm, "AndroidKeyStore")
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAttestationChallenge("RootDetectorChallenge".toByteArray())
                .setCertificateSubject(X500Principal("CN=RootDetector"))

            if (strategy.algorithm == KeyProperties.KEY_ALGORITHM_EC) {
                specBuilder.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            } else {
                specBuilder.setKeySize(2048)
                specBuilder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                specBuilder.setDevicePropertiesAttestationIncluded(true)
            }
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                specBuilder.setIsStrongBoxBacked(true)
            }

            generator.initialize(specBuilder.build())
            generator.generateKeyPair()

            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            val privateKey = entry?.privateKey ?: throw IllegalStateException("Generated key entry was not available")
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java) as? KeyInfo
            val certs = keyStore.getCertificateChain(alias)?.map { it as X509Certificate }.orEmpty()
            if (certs.isEmpty()) throw IllegalStateException("No certificates returned")

            return GeneratedAttestation(
                certs = certs,
                securityLevel = resolveSecurityLevel(keyInfo),
                extensionOid = certs.firstOrNull()?.let(::attestationExtensionOid),
                strategyLabel = strategy.label
            )
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun resolveSecurityLevel(keyInfo: KeyInfo?): SecurityLevel {
        if (keyInfo == null) return SecurityLevel.UNKNOWN
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TEE
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                else -> SecurityLevel.UNKNOWN
            }
        }
        @Suppress("DEPRECATION")
        return if (keyInfo.isInsideSecureHardware) SecurityLevel.TEE else SecurityLevel.SOFTWARE
    }

    private fun hasStrongBoxFeature(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
    }

    private fun fallbackStatus(compromisedBoot: Boolean): CheckStatus {
        return if (compromisedBoot) CheckStatus.FAIL else CheckStatus.WARN
    }

    private fun isBootStateCompromised(): Boolean {
        val flashLocked = getProp("ro.boot.flash.locked").lowercase()
        val vbmetaState = getProp("ro.boot.vbmeta.device_state").lowercase()
        val verifiedBoot = getProp("ro.boot.verifiedbootstate").lowercase()
        val verityMode = getProp("ro.boot.veritymode").lowercase()
        val vbmetaDigest = getProp("ro.boot.vbmeta.digest").lowercase()
        val bootKey = getProp("ro.boot.bootkey").lowercase()
        val unlocked = flashLocked == "0" || vbmetaState == "unlocked"
        val badVerifiedBoot = verifiedBoot == "orange" || verifiedBoot == "red"
        val badVerity = verityMode == "disabled" || verityMode == "logging"
        val zeroDigest = vbmetaDigest.isNotEmpty() && vbmetaDigest != "unknown" && vbmetaDigest.all { it == '0' || it == ':' || it == '-' }
        val zeroBootKey = bootKey.isNotEmpty() && bootKey != "unknown" && bootKey.all { it == '0' || it == ':' || it == '-' }
        return unlocked || badVerifiedBoot || badVerity || zeroDigest || zeroBootKey
    }

    private fun getProp(key: String): String = try {
        val process = Runtime.getRuntime().exec("getprop $key")
        BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
    } catch (_: Exception) { "" }

    private fun attestationExtensionOid(cert: X509Certificate): String? {
        return when {
            cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.25") != null -> "1.3.6.1.4.1.11129.2.1.25"
            cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") != null -> "1.3.6.1.4.1.11129.2.1.17"
            cert.getExtensionValue("1.3.6.1.4.1.236.11.3.23.7") != null -> "1.3.6.1.4.1.236.11.3.23.7"
            else -> null
        }
    }

    private fun verifyChain(certs: List<X509Certificate>): String? {
        if (certs.isEmpty()) return "No certificates returned"
        return try {
            for (i in 0 until certs.size - 1) {
                val cert = certs[i]
                val issuer = certs[i + 1]
                cert.verify(issuer.publicKey)
                cert.checkValidity()
            }
            certs.last().checkValidity()
            null
        } catch (e: Exception) {
            e.message?.take(180) ?: e.javaClass.simpleName
        }
    }

    private fun identifyRoot(root: X509Certificate): RootStatus {
        val encoded = root.publicKey.encoded
        if (encoded.contentEquals(googleRootKey)) return RootStatus.GOOGLE
        if (encoded.contentEquals(aospEcRootKey) || encoded.contentEquals(aospRsaRootKey)) return RootStatus.AOSP
        if (knoxKeys.any { encoded.contentEquals(it) }) return RootStatus.KNOX
        if (loadOemKeys().any { encoded.contentEquals(it.encoded) }) return RootStatus.OEM

        val subject = root.subjectX500Principal.name.lowercase()
        val issuer = root.issuerX500Principal.name.lowercase()
        return when {
            subject.contains("google hardware attestation") ||
                subject.contains("android keystore root") ||
                subject.contains("google cloud attestation") ||
                issuer.contains("google") -> RootStatus.GOOGLE
            subject.contains("samsung") || subject.contains("knox") || issuer.contains("samsung") -> RootStatus.KNOX
            subject.contains("android") && issuer.contains("android") -> RootStatus.AOSP
            else -> RootStatus.UNKNOWN
        }
    }

    private fun loadOemKeys(): Set<PublicKey> {
        val resources = Resources.getSystem()
        val resId = resources.getIdentifier("vendor_required_attestation_certificates", "array", "android")
        if (resId == 0) return emptySet()
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            resources.getStringArray(resId)
                .mapNotNull { pem ->
                    runCatching {
                        val normalized = pem
                            .replace("-BEGIN\nCERTIFICATE-", "-BEGIN CERTIFICATE-")
                            .replace("-END\nCERTIFICATE-", "-END CERTIFICATE-")
                            .replace("\r", "")
                        val stream = ByteArrayInputStream(normalized.toByteArray())
                        (factory.generateCertificate(stream) as X509Certificate).publicKey
                    }.getOrNull()
                }
                .filterNot { it.encoded.contentEquals(googleRootKey) }
                .toSet()
        } catch (_: CertificateException) {
            emptySet()
        }
    }

    private fun securityLevelLabel(level: SecurityLevel): String {
        return when (level) {
            SecurityLevel.SOFTWARE -> "Software"
            SecurityLevel.TEE -> "TEE"
            SecurityLevel.STRONGBOX -> "StrongBox"
            SecurityLevel.UNKNOWN -> "Unknown"
        }
    }

    private fun formatGeneratedDetail(generated: GeneratedAttestation, tail: String?): String {
        return buildString {
            append("Strategy: ${generated.strategyLabel}\n")
            append("Chain depth: ${generated.certs.size}\n")
            append("Security level: ${securityLevelLabel(generated.securityLevel)}\n")
            append("Extension: ${generated.extensionOid ?: "none"}\n")
            append("Root: ${generated.certs.last().subjectX500Principal.name.take(96)}")
            if (!tail.isNullOrBlank()) {
                append("\n")
                append(tail)
            }
        }.trim()
    }

    private fun buildFailureDetail(errors: List<String>): String {
        if (errors.isEmpty()) return "No attestation strategy succeeded"
        return errors.joinToString("\n").take(700)
    }

    private fun decodeKey(value: String): ByteArray =
        Base64.getMimeDecoder().decode(value.replace("\n", "").trim())

    private fun det(
        id: String,
        name: String,
        group: HwGroup,
        status: CheckStatus,
        description: String,
        detail: String?
    ) = HwCheckItem(
        id = id,
        name = name,
        description = description,
        group = group,
        status = status,
        value = when (status) {
            CheckStatus.PASS -> "Verified"
            CheckStatus.FAIL -> "Failed"
            CheckStatus.WARN -> "Warning"
            CheckStatus.UNKNOWN -> "Info"
        },
        detail = detail
    )
}
