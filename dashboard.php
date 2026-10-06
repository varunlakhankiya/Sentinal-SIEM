<?php
session_start();

if (!isset($_SESSION["username"])) {
    header("Location: login.php");
    exit();
}

include "db.php";

$page_title = "SOC Dashboard";
$active_nav = "dashboard";

// Metrics calculations
$total_logs = $conn->query("SELECT COUNT(*) AS c FROM security_logs")->fetch_assoc()['c'] ?? 0;
$critical_threats = $conn->query("SELECT COUNT(*) AS c FROM security_logs WHERE severity = 'CRITICAL'")->fetch_assoc()['c'] ?? 0;
$high_threats = $conn->query("SELECT COUNT(*) AS c FROM security_logs WHERE severity = 'HIGH'")->fetch_assoc()['c'] ?? 0;
$open_alerts = $conn->query("SELECT COUNT(*) AS c FROM alerts WHERE status = 'OPEN'")->fetch_assoc()['c'] ?? 0;
$in_prog_alerts = $conn->query("SELECT COUNT(*) AS c FROM alerts WHERE status = 'IN_PROGRESS'")->fetch_assoc()['c'] ?? 0;
$resolved_alerts = $conn->query("SELECT COUNT(*) AS c FROM alerts WHERE status = 'RESOLVED'")->fetch_assoc()['c'] ?? 0;
$active_rules = $conn->query("SELECT COUNT(*) AS c FROM detection_rules WHERE is_active = 1")->fetch_assoc()['c'] ?? 0;

// Threat Breakdown by Category
$cat_breakdown = $conn->query("
    SELECT category, COUNT(*) as count 
    FROM alerts 
    GROUP BY category 
    ORDER BY count DESC
");

// Top Attacking Source IPs
$top_attackers = $conn->query("
    SELECT source_ip, COUNT(*) as attack_count, MAX(severity) as max_sev 
    FROM security_logs 
    WHERE severity IN ('HIGH', 'CRITICAL') 
    GROUP BY source_ip 
    ORDER BY attack_count DESC 
    LIMIT 5
");

// Recent Incidents
$latest_alerts = $conn->query("
    SELECT * FROM alerts 
    ORDER BY id DESC 
    LIMIT 5
");

// Recent Logs
$latest_logs = $conn->query("
    SELECT * FROM security_logs 
    ORDER BY id DESC 
    LIMIT 6
");

include "header.php";
?>

<div class="container">
    <div class="page-title-bar">
        <div>
            <h2>
                Welcome, <?php echo htmlspecialchars($_SESSION["full_name"] ?? $_SESSION["username"]); ?>!
                <span class="badge badge-info" style="font-size: 12px; margin-left: 6px;"><?php echo htmlspecialchars($_SESSION["role"] ?? "SOC Analyst"); ?></span>
            </h2>
            <p class="subtitle">Real-time Threat Monitoring, Correlation Engine & Incident Triage Console</p>
        </div>
        <div style="display: flex; gap: 8px;">
            <a href="simulator.php" class="btn btn-cyan">&blacktriangleright; Launch Attack Simulator</a>
            <a href="add_log.php" class="btn btn-primary">+ Ingest New Log</a>
        </div>
    </div>

    <!-- Metric Summary Cards -->
    <div class="summary-grid">
        <div class="summary-card critical">
            <h3>Critical Threats</h3>
            <div class="number"><?php echo number_format($critical_threats); ?></div>
            <div class="desc">High impact security alerts</div>
        </div>
        <div class="summary-card high">
            <h3>Open Incidents</h3>
            <div class="number"><?php echo number_format($open_alerts); ?></div>
            <div class="desc">Pending SOC triage</div>
        </div>
        <div class="summary-card info">
            <h3>Total Ingested Logs</h3>
            <div class="number"><?php echo number_format($total_logs); ?></div>
            <div class="desc">System & network events</div>
        </div>
        <div class="summary-card success">
            <h3>Resolved Incidents</h3>
            <div class="number"><?php echo number_format($resolved_alerts); ?></div>
            <div class="desc">Closed & mitigated</div>
        </div>
    </div>

    <!-- Threat Intelligence Grid -->
    <div class="dashboard-grid">
        <!-- Live Alert Feed -->
        <div class="panel">
            <div class="panel-header">
                <h3>Priority Incident Queue</h3>
                <a href="alerts.php" class="btn btn-secondary btn-sm">All Incidents &rarr;</a>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Incident Title</th>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Source IP</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($latest_alerts && $latest_alerts->num_rows > 0): ?>
                            <?php while ($alt = $latest_alerts->fetch_assoc()): ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($alt['title']); ?></strong></td>
                                    <td>
                                        <span class="badge badge-<?php echo strtolower($alt['severity']); ?>">
                                            <?php echo htmlspecialchars($alt['severity']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($alt['category']); ?></td>
                                    <td><span class="code-pill"><?php echo htmlspecialchars($alt['source_ip']); ?></span></td>
                                    <td>
                                        <span class="badge badge-status-<?php echo strtolower($alt['status']); ?>">
                                            <?php echo str_replace('_', ' ', $alt['status']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <a href="alerts.php?id=<?php echo $alt['id']; ?>" class="btn btn-secondary btn-sm">Triage</a>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No active incidents. SOC is clean!</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Threat Breakdown by Category -->
        <div class="panel">
            <div class="panel-header">
                <h3>Threat Distribution</h3>
                <a href="rules.php" class="btn btn-secondary btn-sm">Rules</a>
            </div>

            <?php if ($cat_breakdown && $cat_breakdown->num_rows > 0): ?>
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <?php while ($cat = $cat_breakdown->fetch_assoc()): ?>
                        <div>
                            <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px;">
                                <span><?php echo htmlspecialchars($cat['category']); ?></span>
                                <strong><?php echo $cat['count']; ?> incident(s)</strong>
                            </div>
                            <div style="background: #edebe9; height: 8px; border-radius: 4px; overflow: hidden;">
                                <div style="background: var(--ms-blue); height: 100%; width: <?php echo min(100, $cat['count'] * 25); ?>%;"></div>
                            </div>
                        </div>
                    <?php endwhile; ?>
                </div>
            <?php else: ?>
                <p style="color: var(--text-muted); font-size: 13px;">No category telemetry available yet.</p>
            <?php endif; ?>

            <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border-light);">
                <h4 style="font-size: 12px; margin-bottom: 8px; color: var(--text-secondary); text-transform: uppercase; font-weight: 600;">Top Threat Origin IPs</h4>
                <?php if ($top_attackers && $top_attackers->num_rows > 0): ?>
                    <ul style="list-style: none; font-size: 13px; display: flex; flex-direction: column; gap: 8px;">
                        <?php while ($att = $top_attackers->fetch_assoc()): ?>
                            <li style="display: flex; justify-content: space-between; align-items: center;">
                                <span class="code-pill"><?php echo htmlspecialchars($att['source_ip']); ?></span>
                                <span class="badge badge-<?php echo strtolower($att['max_sev']); ?>"><?php echo $att['attack_count']; ?> attack(s)</span>
                            </li>
                        <?php endwhile; ?>
                    </ul>
                <?php else: ?>
                    <p style="color: var(--text-muted); font-size: 12px;">No malicious IPs detected yet.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Recent Security Logs -->
    <div class="panel">
        <div class="panel-header">
            <h3>Recent Log Telemetry</h3>
            <a href="logs.php" class="btn btn-secondary btn-sm">Open Full Log Explorer &rarr;</a>
        </div>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Dest IP:Port</th>
                        <th>Protocol</th>
                        <th>Event Type</th>
                        <th>Severity</th>
                        <th>Message</th>
                        <th>Triggered Rule</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($latest_logs && $latest_logs->num_rows > 0): ?>
                        <?php while ($log = $latest_logs->fetch_assoc()): ?>
                            <tr>
                                <td><small><?php echo date("Y-m-d H:i:s", strtotime($log['timestamp'])); ?></small></td>
                                <td><span class="code-pill"><?php echo htmlspecialchars($log['source_ip']); ?></span></td>
                                <td><span class="code-pill"><?php echo htmlspecialchars($log['dest_ip']) . ":" . $log['port']; ?></span></td>
                                <td><strong><?php echo htmlspecialchars($log['protocol']); ?></strong></td>
                                <td><?php echo htmlspecialchars($log['event_type']); ?></td>
                                <td>
                                    <span class="badge badge-<?php echo strtolower($log['severity']); ?>">
                                        <?php echo htmlspecialchars($log['severity']); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars(mb_strimwidth($log['message'], 0, 50, "...")); ?></td>
                                <td>
                                    <?php if (!empty($log['rule_triggered'])): ?>
                                        <span class="badge badge-critical"><?php echo htmlspecialchars($log['rule_triggered']); ?></span>
                                    <?php else: ?>
                                        <span style="color: var(--text-muted); font-size: 12px;">&mdash;</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No log records found.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php include "footer.php"; ?>
