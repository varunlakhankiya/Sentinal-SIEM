<?php
session_start();

if (!isset($_SESSION["username"])) {
    header("Location: login.php");
    exit();
}

include "db.php";

$page_title = "Event Logs";
$active_nav = "logs";

// Handle log deletion if requested
if (isset($_GET['delete_id'])) {
    $del_id = intval($_GET['delete_id']);
    $conn->query("DELETE FROM security_logs WHERE id = $del_id");
    header("Location: logs.php?msg=deleted");
    exit();
}

// Filter parameters
$filter_severity = trim($_GET['severity'] ?? '');
$filter_type = trim($_GET['event_type'] ?? '');
$filter_search = trim($_GET['search'] ?? '');

// Build query
$where_clauses = [];

if (!empty($filter_severity)) {
    $sev_esc = $conn->real_escape_string($filter_severity);
    $where_clauses[] = "severity = '$sev_esc'";
}

if (!empty($filter_type)) {
    $type_esc = $conn->real_escape_string($filter_type);
    $where_clauses[] = "event_type = '$type_esc'";
}

if (!empty($filter_search)) {
    $search_esc = $conn->real_escape_string($filter_search);
    $where_clauses[] = "(source_ip LIKE '%$search_esc%' OR dest_ip LIKE '%$search_esc%' OR message LIKE '%$search_esc%' OR username LIKE '%$search_esc%')";
}

$where_sql = "";
if (count($where_clauses) > 0) {
    $where_sql = "WHERE " . implode(" AND ", $where_clauses);
}

$logs_query = "SELECT * FROM security_logs $where_sql ORDER BY id DESC";
$logs_result = $conn->query($logs_query);
$log_count = $logs_result ? $logs_result->num_rows : 0;

include "header.php";
?>

<div class="container">
    <div class="page-title-bar">
        <div>
            <h2>Security Event Telemetry Logs</h2>
            <p class="subtitle">Search, filter, and inspect ingested raw event records (Total: <?php echo $log_count; ?> entries)</p>
        </div>
        <div>
            <a href="add_log.php" class="btn btn-primary">+ Ingest Event</a>
            <a href="simulator.php" class="btn btn-cyan">Simulate Traffic</a>
        </div>
    </div>

    <?php if (isset($_GET['msg']) && $_GET['msg'] === 'deleted'): ?>
        <div class="alert-box alert-info">
            &check; Log entry successfully removed from SIEM telemetry store.
        </div>
    <?php endif; ?>

    <!-- Filter Bar -->
    <form method="GET" action="logs.php" class="filter-bar">
        <div class="filter-item">
            <label for="search">Search IP / Payload</label>
            <input type="text" id="search" name="search" placeholder="e.g. 192.168.1.1, root, UNION" value="<?php echo htmlspecialchars($filter_search); ?>">
        </div>

        <div class="filter-item">
            <label for="severity">Severity</label>
            <select id="severity" name="severity">
                <option value="">All Severities</option>
                <option value="INFO" <?php if ($filter_severity === 'INFO') echo 'selected'; ?>>INFO</option>
                <option value="LOW" <?php if ($filter_severity === 'LOW') echo 'selected'; ?>>LOW</option>
                <option value="MEDIUM" <?php if ($filter_severity === 'MEDIUM') echo 'selected'; ?>>MEDIUM</option>
                <option value="HIGH" <?php if ($filter_severity === 'HIGH') echo 'selected'; ?>>HIGH</option>
                <option value="CRITICAL" <?php if ($filter_severity === 'CRITICAL') echo 'selected'; ?>>CRITICAL</option>
            </select>
        </div>

        <div class="filter-item">
            <label for="event_type">Event Type</label>
            <select id="event_type" name="event_type">
                <option value="">All Event Types</option>
                <option value="Web Attack" <?php if ($filter_type === 'Web Attack') echo 'selected'; ?>>Web Attack</option>
                <option value="Brute Force" <?php if ($filter_type === 'Brute Force') echo 'selected'; ?>>Brute Force</option>
                <option value="Port Scan" <?php if ($filter_type === 'Port Scan') echo 'selected'; ?>>Port Scan</option>
                <option value="Privilege Escalation" <?php if ($filter_type === 'Privilege Escalation') echo 'selected'; ?>>Privilege Escalation</option>
                <option value="Auth Success" <?php if ($filter_type === 'Auth Success') echo 'selected'; ?>>Auth Success</option>
                <option value="Auth Failure" <?php if ($filter_type === 'Auth Failure') echo 'selected'; ?>>Auth Failure</option>
                <option value="DNS Query" <?php if ($filter_type === 'DNS Query') echo 'selected'; ?>>DNS Query</option>
            </select>
        </div>

        <div>
            <button type="submit" class="btn btn-secondary">Apply Filters</button>
            <a href="logs.php" class="btn btn-secondary">Reset</a>
        </div>
    </form>

    <!-- Logs Table -->
    <div class="panel">
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Destination</th>
                        <th>Proto</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>User</th>
                        <th>Event Message / Payload</th>
                        <th>Action</th>
                        <?php if (isset($_SESSION["username"])): ?>
                            <th>Manage</th>
                        <?php endif; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($logs_result && $logs_result->num_rows > 0): ?>
                        <?php while ($log = $logs_result->fetch_assoc()): ?>
                            <tr>
                                <td>#<?php echo $log['id']; ?></td>
                                <td><small><?php echo date("Y-m-d H:i:s", strtotime($log['timestamp'])); ?></small></td>
                                <td><span class="code-pill"><?php echo htmlspecialchars($log['source_ip']); ?></span></td>
                                <td><span class="code-pill"><?php echo htmlspecialchars($log['dest_ip']) . ":" . $log['port']; ?></span></td>
                                <td><?php echo htmlspecialchars($log['protocol']); ?></td>
                                <td><strong><?php echo htmlspecialchars($log['event_type']); ?></strong></td>
                                <td>
                                    <span class="badge badge-<?php echo strtolower($log['severity']); ?>">
                                        <?php echo htmlspecialchars($log['severity']); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($log['username']); ?></td>
                                <td>
                                    <?php echo htmlspecialchars($log['message']); ?>
                                    <?php if (!empty($log['rule_triggered'])): ?>
                                        <div style="margin-top: 4px;">
                                            <span class="badge badge-critical">&bull; Matched Rule: <?php echo htmlspecialchars($log['rule_triggered']); ?></span>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td><span class="badge badge-info"><?php echo htmlspecialchars($log['action_taken']); ?></span></td>
                                <?php if (isset($_SESSION["username"])): ?>
                                    <td>
                                        <a href="logs.php?delete_id=<?php echo $log['id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Delete log record #<?php echo $log['id']; ?>?')">Delete</a>
                                    </td>
                                <?php endif; ?>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="11" style="text-align: center; padding: 32px; color: var(--text-muted);">
                                No security logs matching your criteria.
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php include "footer.php"; ?>
