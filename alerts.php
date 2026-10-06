<?php
session_start();

if (!isset($_SESSION["username"])) {
    header("Location: login.php");
    exit();
}

include "db.php";

$page_title = "Incidents & Alerts";
$active_nav = "alerts";

$msg = "";
$msg_type = "alert-info";

// Update alert status/notes
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["update_alert"])) {
    $alert_id = intval($_POST["alert_id"] ?? 0);
    $status = trim($_POST["status"] ?? "OPEN");
    $assigned_to = trim($_POST["assigned_to"] ?? "Unassigned");
    $analyst_notes = trim($_POST["analyst_notes"] ?? "");

    if ($alert_id > 0) {
        $stmt = $conn->prepare("UPDATE alerts SET status = ?, assigned_to = ?, analyst_notes = ? WHERE id = ?");
        $stmt->bind_param("sssi", $status, $assigned_to, $analyst_notes, $alert_id);
        if ($stmt->execute()) {
            $msg = "Incident #$alert_id successfully updated to status: " . str_replace('_', ' ', $status);
            $msg_type = "alert-success";
        } else {
            $msg = "Failed to update incident: " . $conn->error;
            $msg_type = "alert-error";
        }
    }
}

// Delete alert
if (isset($_GET['delete_alert_id'])) {
    $del_id = intval($_GET['delete_alert_id']);
    $conn->query("DELETE FROM alerts WHERE id = $del_id");
    header("Location: alerts.php?msg=deleted");
    exit();
}

// Filters
$filter_status = trim($_GET['status'] ?? '');
$filter_sev = trim($_GET['severity'] ?? '');
$focused_id = intval($_GET['id'] ?? 0);

$where_clauses = [];
if (!empty($filter_status)) {
    $status_esc = $conn->real_escape_string($filter_status);
    $where_clauses[] = "status = '$status_esc'";
}
if (!empty($filter_sev)) {
    $sev_esc = $conn->real_escape_string($filter_sev);
    $where_clauses[] = "severity = '$sev_esc'";
}
if ($focused_id > 0) {
    $where_clauses[] = "id = $focused_id";
}

$where_sql = "";
if (count($where_clauses) > 0) {
    $where_sql = "WHERE " . implode(" AND ", $where_clauses);
}

$alerts_res = $conn->query("SELECT * FROM alerts $where_sql ORDER BY id DESC");

// Fetch counts
$open_count = $conn->query("SELECT COUNT(*) AS c FROM alerts WHERE status='OPEN'")->fetch_assoc()['c'] ?? 0;
$in_prog_count = $conn->query("SELECT COUNT(*) AS c FROM alerts WHERE status='IN_PROGRESS'")->fetch_assoc()['c'] ?? 0;
$resolved_count = $conn->query("SELECT COUNT(*) AS c FROM alerts WHERE status='RESOLVED'")->fetch_assoc()['c'] ?? 0;

include "header.php";
?>

<div class="container">
    <div class="page-title-bar">
        <div>
            <h2>Security Incidents & Alert Triage</h2>
            <p class="subtitle">Correlated threat incidents requiring SOC analyst triage, root-cause investigation, and containment</p>
        </div>
        <div>
            <a href="simulator.php" class="btn btn-cyan">Simulate Attack</a>
        </div>
    </div>

    <?php if (isset($_GET['msg']) && $_GET['msg'] === 'deleted'): ?>
        <div class="alert-box alert-info">&check; Incident removed successfully.</div>
    <?php elseif (!empty($msg)): ?>
        <div class="alert-box <?php echo $msg_type; ?>">
            <?php echo htmlspecialchars($msg); ?>
        </div>
    <?php endif; ?>

    <!-- Status summary pills -->
    <div class="summary-grid" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom: 20px;">
        <a href="alerts.php?status=OPEN" style="text-decoration: none;">
            <div class="summary-card critical">
                <h3>Open Incidents</h3>
                <div class="number"><?php echo $open_count; ?></div>
            </div>
        </a>
        <a href="alerts.php?status=IN_PROGRESS" style="text-decoration: none;">
            <div class="summary-card high">
                <h3>In Progress</h3>
                <div class="number"><?php echo $in_prog_count; ?></div>
            </div>
        </a>
        <a href="alerts.php?status=RESOLVED" style="text-decoration: none;">
            <div class="summary-card success">
                <h3>Resolved</h3>
                <div class="number"><?php echo $resolved_count; ?></div>
            </div>
        </a>
    </div>

    <!-- Filter Bar -->
    <form method="GET" action="alerts.php" class="filter-bar">
        <div class="filter-item">
            <label for="status">Status Filter</label>
            <select id="status" name="status">
                <option value="">All Statuses</option>
                <option value="OPEN" <?php if ($filter_status === 'OPEN') echo 'selected'; ?>>OPEN</option>
                <option value="IN_PROGRESS" <?php if ($filter_status === 'IN_PROGRESS') echo 'selected'; ?>>IN PROGRESS</option>
                <option value="RESOLVED" <?php if ($filter_status === 'RESOLVED') echo 'selected'; ?>>RESOLVED</option>
                <option value="FALSE_POSITIVE" <?php if ($filter_status === 'FALSE_POSITIVE') echo 'selected'; ?>>FALSE POSITIVE</option>
            </select>
        </div>

        <div class="filter-item">
            <label for="severity">Severity Filter</label>
            <select id="severity" name="severity">
                <option value="">All Severities</option>
                <option value="CRITICAL" <?php if ($filter_sev === 'CRITICAL') echo 'selected'; ?>>CRITICAL</option>
                <option value="HIGH" <?php if ($filter_sev === 'HIGH') echo 'selected'; ?>>HIGH</option>
                <option value="MEDIUM" <?php if ($filter_sev === 'MEDIUM') echo 'selected'; ?>>MEDIUM</option>
                <option value="LOW" <?php if ($filter_sev === 'LOW') echo 'selected'; ?>>LOW</option>
            </select>
        </div>

        <div>
            <button type="submit" class="btn btn-secondary">Filter Incidents</button>
            <a href="alerts.php" class="btn btn-secondary">Clear</a>
        </div>
    </form>

    <!-- Incidents Table / Cards -->
    <div class="panel">
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Incident Title</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Attacker IP</th>
                        <th>Status</th>
                        <th>Assigned</th>
                        <th>Analyst Notes / Triage</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($alerts_res && $alerts_res->num_rows > 0): ?>
                        <?php while ($alt = $alerts_res->fetch_assoc()): ?>
                            <tr style="<?php echo ($focused_id == $alt['id']) ? 'background: #eff6fc;' : ''; ?>">
                                <td>#<?php echo $alt['id']; ?></td>
                                <td><small><?php echo date("Y-m-d H:i", strtotime($alt['timestamp'])); ?></small></td>
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
                                <td><?php echo htmlspecialchars($alt['assigned_to']); ?></td>
                                <td style="max-width: 250px;">
                                    <form method="POST" action="alerts.php" style="display: flex; flex-direction: column; gap: 6px;">
                                        <input type="hidden" name="update_alert" value="1">
                                        <input type="hidden" name="alert_id" value="<?php echo $alt['id']; ?>">
                                        
                                        <input type="text" name="analyst_notes" placeholder="Mitigation notes..." value="<?php echo htmlspecialchars($alt['analyst_notes'] ?? ''); ?>" style="padding: 4px 8px; font-size: 12px;">
                                        
                                        <div style="display: flex; gap: 4px;">
                                            <select name="status" style="padding: 3px 6px; font-size: 12px;">
                                                <option value="OPEN" <?php if ($alt['status'] === 'OPEN') echo 'selected'; ?>>OPEN</option>
                                                <option value="IN_PROGRESS" <?php if ($alt['status'] === 'IN_PROGRESS') echo 'selected'; ?>>IN PROGRESS</option>
                                                <option value="RESOLVED" <?php if ($alt['status'] === 'RESOLVED') echo 'selected'; ?>>RESOLVED</option>
                                                <option value="FALSE_POSITIVE" <?php if ($alt['status'] === 'FALSE_POSITIVE') echo 'selected'; ?>>FALSE POSITIVE</option>
                                            </select>

                                            <select name="assigned_to" style="padding: 3px 6px; font-size: 12px;">
                                                <option value="Unassigned" <?php if ($alt['assigned_to'] === 'Unassigned') echo 'selected'; ?>>Unassigned</option>
                                                <option value="admin" <?php if ($alt['assigned_to'] === 'admin') echo 'selected'; ?>>admin</option>
                                                <option value="SOC Lead" <?php if ($alt['assigned_to'] === 'SOC Lead') echo 'selected'; ?>>SOC Lead</option>
                                                <option value="Tier-1 Analyst" <?php if ($alt['assigned_to'] === 'Tier-1 Analyst') echo 'selected'; ?>>Tier-1 Analyst</option>
                                            </select>

                                            <button type="submit" class="btn btn-secondary btn-sm" title="Save triage update">Save</button>
                                        </div>
                                    </form>
                                </td>
                                <td>
                                    <a href="alerts.php?delete_alert_id=<?php echo $alt['id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Delete incident #<?php echo $alt['id']; ?>?')">Delete</a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr><td colspan="10" style="text-align: center; padding: 28px; color: var(--text-muted);">No security alerts found.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php include "footer.php"; ?>
