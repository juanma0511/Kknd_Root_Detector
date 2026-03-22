package com.juanma0511.rootdetector.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.juanma0511.rootdetector.MainViewModel
import com.juanma0511.rootdetector.model.*

@Composable
fun HwSecurityScreen(viewModel: MainViewModel) {
    val scanState     by viewModel.hwScanState.collectAsState()
    val scanProgress  by viewModel.hwScanProgress.collectAsState()
    val scanResult    by viewModel.hwScanResult.collectAsState()

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        
        item {
            HwHeroCard(
                scanState = scanState,
                scanProgress = scanProgress,
                scanResult = scanResult,
                onScanClick = { viewModel.startHwScan() },
                onReset = { viewModel.resetHwScan() }
            )
        }
        if (scanResult != null) {
            
            item { HwSummaryRow(scanResult!!) }

            val groups = HwGroup.values().filter { g ->
                scanResult!!.items.any { it.group == g }
            }

            groups.forEach { group ->
                item {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.padding(top = 8.dp, bottom = 2.dp)
                    ) {
                        Icon(
                            imageVector = groupIcon(group),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            groupLabel(group),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                val groupItems = scanResult!!.items
                    .filter { it.group == group }
                    .sortedBy { it.status.ordinal }
                items(groupItems) { item -> HwCheckCard(item) }
            }

            item { Spacer(Modifier.height(8.dp)) }
        }
    }
}

@Composable
fun HwHeroCard(
    scanState: HwScanState,
    scanProgress: Int,
    scanResult: HwScanResult?,
    onScanClick: () -> Unit,
    onReset: () -> Unit
) {
    val animatedProgress by animateFloatAsState(
        targetValue = scanProgress / 100f,
        animationSpec = tween(300),
        label = "hw_progress"
    )

    val statusColor = when {
        scanResult == null -> MaterialTheme.colorScheme.secondary
        scanResult.failCount > 0 -> MaterialTheme.colorScheme.error
        scanResult.warnCount > 0 -> MaterialTheme.colorScheme.tertiary
        else -> Color(0xFF2E7D32)
    }
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val containerColor = when {
        scanResult == null      -> if (isDark) Color(0xFF0D1B2E) else Color(0xFFDCE8FF)
        scanResult.failCount > 0 -> if (isDark) Color(0xFF2E0A0A) else Color(0xFFFFDAD6)
        scanResult.warnCount > 0 -> if (isDark) Color(0xFF2A1A00) else Color(0xFFFFDBC8)
        else                    -> if (isDark) Color(0xFF0A1F0A) else Color(0xFFE8F5E9)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        elevation = CardDefaults.cardElevation(0.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            val iconScale by animateFloatAsState(
                targetValue = if (scanState == HwScanState.SCANNING) 0.9f else 1f,
                animationSpec = if (scanState == HwScanState.SCANNING)
                    infiniteRepeatable(tween(700), RepeatMode.Reverse)
                else spring(),
                label = "hw_scale"
            )
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(88.dp)
                    .scale(iconScale)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = if (isDark) 0.24f else 0.12f))
            ) {
                Icon(
                    imageVector = when {
                        scanState == HwScanState.SCANNING -> Icons.Outlined.Memory
                        (scanResult?.failCount ?: 0) > 0 -> Icons.Filled.LockOpen
                        (scanResult?.warnCount ?: 0) > 0 -> Icons.Filled.Warning
                        scanResult != null -> Icons.Filled.Lock
                        else -> Icons.Outlined.Hardware
                    },
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(48.dp)
                )
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text = when {
                    scanState == HwScanState.IDLE -> "Hardware Security"
                    scanState == HwScanState.SCANNING -> "Analyzing..."
                    (scanResult?.failCount ?: 0) > 0 -> "${scanResult!!.failCount} Critical Findings"
                    (scanResult?.warnCount ?: 0) > 0 -> "${scanResult!!.warnCount} Warnings"
                    scanResult != null -> "All Checks Passed"
                    else -> "Hardware Security"
                },
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = statusColor
            )
            Text(
                text = when {
                    scanState == HwScanState.IDLE -> "TEE · StrongBox · VBMeta · Verified Boot"
                    scanState == HwScanState.SCANNING -> "$scanProgress% complete"
                    scanResult != null ->
                        "${scanResult.passCount} passed · ${scanResult.warnCount} warn · ${scanResult.failCount} failed"
                    else -> ""
                },
                style = MaterialTheme.typography.bodyMedium,
                color = statusColor.copy(alpha = 0.8f),
                modifier = Modifier.padding(top = 4.dp)
            )

            Spacer(Modifier.height(20.dp))

            AnimatedContent(
                targetState = scanState,
                transitionSpec = { fadeIn(tween(300)) togetherWith fadeOut(tween(200)) },
                label = "hw_action"
            ) { state ->
                when (state) {
                    HwScanState.IDLE -> {
                        Button(
                            onClick = onScanClick,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = statusColor)
                        ) {
                            Icon(Icons.Outlined.PlayArrow, null, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Analyze Hardware Security", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                        }
                    }
                    HwScanState.DONE -> {
                        Button(
                            onClick = onReset,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = statusColor)
                        ) {
                            Icon(Icons.Filled.Refresh, null, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Scan Again", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                        }
                    }
                    HwScanState.SCANNING -> {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            LinearProgressIndicator(
                                progress = { animatedProgress },
                                modifier = Modifier.fillMaxWidth().height(8.dp).clip(CircleShape),
                                color = statusColor,
                                trackColor = statusColor.copy(alpha = 0.2f)
                            )
                            Spacer(Modifier.height(8.dp))
                            Text("$scanProgress%", style = MaterialTheme.typography.labelLarge, color = statusColor)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun HwSummaryRow(result: HwScanResult) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SummaryChip("${result.failCount} Failed", MaterialTheme.colorScheme.error, selected = false, modifier = Modifier.weight(1f), onClick = {})
        SummaryChip("${result.warnCount} Warn", MaterialTheme.colorScheme.tertiary, selected = false, modifier = Modifier.weight(1f), onClick = {})
        SummaryChip("${result.passCount} Pass", Color(0xFF2E7D32), selected = false, modifier = Modifier.weight(1f), onClick = {})
    }
}

@Composable
fun HwCheckCard(item: HwCheckItem) {
    var expanded by remember { mutableStateOf(false) }
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    
    val statusColor = when (item.status) {
        CheckStatus.PASS    -> Color(0xFF2E7D32)
        CheckStatus.WARN    -> MaterialTheme.colorScheme.tertiary
        CheckStatus.FAIL    -> MaterialTheme.colorScheme.error
        CheckStatus.UNKNOWN -> MaterialTheme.colorScheme.outline
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = when (item.status) {
                CheckStatus.PASS    -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (isDark) 0.32f else 0.4f)
                CheckStatus.WARN    -> MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = if (isDark) 0.22f else 0.35f)
                CheckStatus.FAIL    -> MaterialTheme.colorScheme.errorContainer.copy(alpha = if (isDark) 0.22f else 0.35f)
                CheckStatus.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (isDark) 0.24f else 0.3f)
            }
        ),
        elevation = CardDefaults.cardElevation(0.dp),
        onClick = { if (item.detail != null || item.expected != null) expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = if (isDark) 0.85f else 0.65f))
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(item.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                    Text(
                        item.value,
                        style = MaterialTheme.typography.bodySmall,
                        color = statusColor,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Surface(shape = RoundedCornerShape(6.dp), color = statusColor.copy(alpha = if (isDark) 0.24f else 0.15f)) {
                    Text(
                        when (item.status) {
                            CheckStatus.PASS    -> "PASS"
                            CheckStatus.WARN    -> "WARN"
                            CheckStatus.FAIL    -> "FAIL"
                            CheckStatus.UNKNOWN -> "INFO"
                        },
                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = statusColor
                    )
                }
                if (item.detail != null || item.expected != null) {
                    Icon(
                        if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 10.dp)) {
                    HorizontalDivider(color = statusColor.copy(alpha = 0.2f))
                    Spacer(Modifier.height(8.dp))
                    Text(
                        item.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    item.expected?.let {
                        Spacer(Modifier.height(4.dp))
                        Row {
                            Text("Expected: ", style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(it, style = MaterialTheme.typography.labelSmall,
                                color = Color(0xFF2E7D32), fontFamily = FontFamily.Monospace)
                        }
                    }
                    item.detail?.let {
                        Spacer(Modifier.height(4.dp))
                        Surface(shape = RoundedCornerShape(8.dp), color = statusColor.copy(alpha = if (isDark) 0.18f else 0.1f)) {
                            Text(
                                it,
                                modifier = Modifier.padding(8.dp),
                                style = MaterialTheme.typography.bodySmall,
                                color = statusColor,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun groupLabel(group: HwGroup) = when (group) {
    HwGroup.KEYSTORE     -> "Keystore / TEE / StrongBox"
    HwGroup.BOOT         -> "Verified Boot"
    HwGroup.VBMETA       -> "VBMeta / AVB"
    HwGroup.SYSTEM_PROPS -> "System Properties"
}

private fun groupIcon(group: HwGroup): androidx.compose.ui.graphics.vector.ImageVector = when (group) {
    HwGroup.KEYSTORE     -> Icons.Outlined.Key
    HwGroup.BOOT         -> Icons.Outlined.VerifiedUser
    HwGroup.VBMETA       -> Icons.Outlined.Security
    HwGroup.SYSTEM_PROPS -> Icons.Outlined.Settings
}
