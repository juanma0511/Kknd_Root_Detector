package com.juanma0511.rootdetector.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.juanma0511.rootdetector.MainViewModel
import com.juanma0511.rootdetector.model.*

@Composable
fun RootDetectorScreen(viewModel: MainViewModel) {
    val scanState by viewModel.scanState.collectAsState()
    val scanProgress by viewModel.scanProgress.collectAsState()
    val scanResult by viewModel.scanResult.collectAsState()
    var selectedSeverity by rememberSaveable { mutableStateOf<Severity?>(null) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            StatusHeroCard(
                scanState = scanState,
                scanProgress = scanProgress,
                scanResult = scanResult,
                onScanClick = { viewModel.startScan() }
            )
        }

        if (scanState == ScanState.DONE && scanResult != null) {
            item {
                SummaryRow(
                    result = scanResult!!,
                    selectedSeverity = selectedSeverity,
                    onSeverityClick = { severity ->
                        selectedSeverity = if (selectedSeverity == severity) null else severity
                    }
                )
            }
        }

        if (scanState == ScanState.DONE && scanResult != null) {
            val filteredItems = scanResult!!.items.filter { item ->
                selectedSeverity == null || item.severity == selectedSeverity
            }
            val grouped = filteredItems.sortedWith(
                compareByDescending<DetectionItem> { it.detected }
                    .thenBy { it.severity.ordinal }
            )
            items(grouped) { item ->
                DetectionItemCard(item)
            }
        }
    }
}

@Composable
fun StatusHeroCard(
    scanState: ScanState,
    scanProgress: Int,
    scanResult: ScanResult?,
    onScanClick: () -> Unit
) {
    val animatedProgress by animateFloatAsState(
        targetValue = scanProgress / 100f,
        animationSpec = tween(300),
        label = "progress"
    )

    val statusColor = when {
        scanResult == null -> MaterialTheme.colorScheme.primary
        scanResult.isRooted -> MaterialTheme.colorScheme.error
        scanResult.isSuspicious -> MaterialTheme.colorScheme.tertiary
        else -> Color(0xFF2E7D32)
    }

    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val containerColor = when {
        scanResult == null  -> if (isDark) Color(0xFF0D1B2E) else Color(0xFFDCE8FF)
        scanResult.isRooted -> if (isDark) Color(0xFF2E0A0A) else Color(0xFFFFDAD6)
        scanResult.isSuspicious -> if (isDark) Color(0xFF2A1A00) else Color(0xFFFFDBC8)
        else                -> if (isDark) Color(0xFF0A1F0A) else Color(0xFFE8F5E9)
    }

    val iconScale by animateFloatAsState(
        targetValue = if (scanState == ScanState.SCANNING) 0.9f else 1f,
        animationSpec = if (scanState == ScanState.SCANNING) {
            infiniteRepeatable(animation = tween(800), repeatMode = RepeatMode.Reverse)
        } else spring(),
        label = "scale"
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
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
                        scanState == ScanState.SCANNING -> Icons.Outlined.Search
                        scanResult?.isRooted == true -> Icons.Filled.Warning
                        scanResult?.isSuspicious == true -> Icons.Filled.Info
                        scanResult != null -> Icons.Filled.CheckCircle
                        else -> Icons.Outlined.Shield
                    },
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(48.dp)
                )
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text = when {
                    scanState == ScanState.IDLE -> "Ready to Scan"
                    scanState == ScanState.SCANNING -> "Scanning..."
                    scanResult?.isRooted == true -> "Root Detected"
                    scanResult?.isSuspicious == true -> "Suspicious"
                    scanResult != null -> "Device Clean"
                    else -> "Ready to Scan"
                },
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = statusColor
            )

            Text(
                text = when {
                    scanState == ScanState.IDLE -> "Tap below to run a full security analysis"
                    scanState == ScanState.SCANNING -> "Running $scanProgress% of checks..."
                    scanResult?.isRooted == true ->
                        "${scanResult.detectedCount} indicators found · ${scanResult.highRiskCount} high risk"
                    scanResult?.isSuspicious == true ->
                        "${scanResult.detectedCount} low-risk indicators found"
                    scanResult != null -> "All ${scanResult.items.size} checks passed"
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
                label = "action"
            ) { state ->
                when (state) {
                    ScanState.IDLE, ScanState.DONE -> {
                        Button(
                            onClick = onScanClick,
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = statusColor)
                        ) {
                            Icon(
                                imageVector = if (state == ScanState.DONE) Icons.Filled.Refresh
                                else Icons.Outlined.PlayArrow,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                if (state == ScanState.DONE) "Scan Again" else "Start Scan",
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 16.sp
                            )
                        }
                    }
                    ScanState.SCANNING -> {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            LinearProgressIndicator(
                                progress = { animatedProgress },
                                modifier = Modifier.fillMaxWidth().height(8.dp).clip(CircleShape),
                                color = statusColor,
                                trackColor = statusColor.copy(alpha = 0.2f)
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "$scanProgress%",
                                style = MaterialTheme.typography.labelLarge,
                                color = statusColor
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SummaryRow(
    result: ScanResult,
    selectedSeverity: Severity?,
    onSeverityClick: (Severity) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        SummaryChip(
            label = "${result.highRiskCount} High",
            color = MaterialTheme.colorScheme.error,
            selected = selectedSeverity == Severity.HIGH,
            modifier = Modifier.weight(1f),
            onClick = { onSeverityClick(Severity.HIGH) }
        )
        SummaryChip(
            label = "${result.mediumRiskCount} Medium",
            color = MaterialTheme.colorScheme.tertiary,
            selected = selectedSeverity == Severity.MEDIUM,
            modifier = Modifier.weight(1f),
            onClick = { onSeverityClick(Severity.MEDIUM) }
        )
        SummaryChip(
            label = "${result.lowRiskCount} Low",
            color = MaterialTheme.colorScheme.primary,
            selected = selectedSeverity == Severity.LOW,
            modifier = Modifier.weight(1f),
            onClick = { onSeverityClick(Severity.LOW) }
        )
    }
}

@Composable
fun SummaryChip(
    label: String,
    color: Color,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f
    val containerAlpha = when {
        selected && isDark -> 0.32f
        selected -> 0.2f
        isDark -> 0.2f
        else -> 0.12f
    }
    val borderColor = if (selected) color.copy(alpha = if (isDark) 0.85f else 0.55f) else Color.Transparent
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = color.copy(alpha = containerAlpha),
        border = androidx.compose.foundation.BorderStroke(1.dp, borderColor)
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .clickable(onClick = onClick)
                .padding(vertical = 10.dp)
        ) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = color
            )
        }
    }
}

@Composable
fun DetectionItemCard(item: DetectionItem) {
    var expanded by remember { mutableStateOf(false) }
    val isDark = MaterialTheme.colorScheme.surface.luminance() < 0.5f

    val severityColor = when (item.severity) {
        Severity.HIGH   -> MaterialTheme.colorScheme.error
        Severity.MEDIUM -> MaterialTheme.colorScheme.tertiary
        Severity.LOW    -> MaterialTheme.colorScheme.primary
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (item.detected)
                severityColor.copy(alpha = if (isDark) 0.14f else 0.06f)
            else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (isDark) 0.32f else 0.5f)
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        onClick = {
            if (item.detected) expanded = !expanded
        }
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(
                            if (item.detected) severityColor.copy(alpha = if (isDark) 0.24f else 0.15f)
                            else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (isDark) 0.7f else 1f)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = categoryIcon(item.category),
                        contentDescription = null,
                        tint = if (item.detected) severityColor
                               else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.size(20.dp)
                    )
                }

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        item.name,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = if (item.detected) MaterialTheme.colorScheme.onSurface
                                else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        item.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = if (item.detected) severityColor.copy(alpha = if (isDark) 0.24f else 0.15f)
                            else Color(0xFF2E7D32).copy(alpha = if (isDark) 0.2f else 0.12f)
                ) {
                    Text(
                        if (item.detected) "FOUND" else "PASS",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (item.detected) severityColor else Color(0xFF2E7D32)
                    )
                }
            }

            AnimatedVisibility(visible = expanded && item.detected) {
                Column {
                    Spacer(Modifier.height(10.dp))
                    HorizontalDivider(color = severityColor.copy(alpha = 0.2f))
                    Spacer(Modifier.height(10.dp))

                    if (item.detail != null) {
                        Text(
                            "Detail",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            item.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = severityColor,
                            fontFamily = FontFamily.Monospace
                        )
                        Spacer(Modifier.height(12.dp))
                    }

                }
            }
        }
    }
}

private fun categoryIcon(category: DetectionCategory): ImageVector = when (category) {
    DetectionCategory.SU_BINARIES   -> Icons.Outlined.Terminal
    DetectionCategory.ROOT_APPS     -> Icons.Outlined.Apps
    DetectionCategory.SYSTEM_PROPS  -> Icons.Outlined.Settings
    DetectionCategory.MOUNT_POINTS  -> Icons.Outlined.FolderOpen
    DetectionCategory.BUILD_TAGS    -> Icons.Outlined.Label
    DetectionCategory.BUSYBOX       -> Icons.Outlined.Code
    DetectionCategory.WRITABLE_PATHS -> Icons.Outlined.Lock
    DetectionCategory.MAGISK        -> Icons.Outlined.Security
    DetectionCategory.FRIDA         -> Icons.Outlined.BugReport
    DetectionCategory.EMULATOR      -> Icons.Outlined.PhoneAndroid
    DetectionCategory.CUSTOM_ROM    -> Icons.Outlined.Smartphone
}
