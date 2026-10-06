<?php
session_start();

if (!isset($_SESSION["username"])) {
    header("Location: login.php");
    exit();
}

include "db.php";

$page_title = "Ingest Log";
$active_nav = "add_log";

$message_status = "";
$message_type = "";
$triggered_rule_info = null;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $source_ip   = trim($_POST["source_ip"] ?? "");
    $dest_ip     = trim($_POST["dest_ip"] ?? "");
    $port        = intval($_POST["port"] ?? 80);
    $protocol    = trim($_POST["protocol"] ?? "HTTP");
    $event_type  = trim($_POST["event_type"] ?? "Generic");
    $severity    = trim($_POST["severity"] ?? "INFO");
    $username    = trim($_POST["username"] ?? "system");
    $log_msg     = trim($_POST["message"] ?? "");
    $action_taken= trim($_POST["action_taken"] ?? "Logged");

    if (!empty($source_ip) && !empty($dest_ip) && !empty($log_msg)) {
        $stmt = $conn->prepare("
            INSERT INTO security_logs (source_ip, dest_ip, port, protocol, event_type, severity, username, message, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->bind_param("ssissssss", $source_ip, $dest_ip, $port, $protocol, $event_type, $severity, $username, $log_msg, $action_taken);

        if ($stmt->execute()) {
            $inserted_id = $stmt->insert_id;
            
            // Run through SIEM Correlation & Detection Engine
            $eval = evaluateSiemRule($conn, $inserted_id, $log_msg, $source_ip, $event_type);

            if ($eval['matched']) {
                $message_status = "Log ingested! ⚠️ SIEM Alert Generated: Detected '" . htmlspecialchars($eval['rule_name']) . "' with " . $eval['severity'] . " severity. Incident logged.";
                $message_type = "alert-error";
                $triggered_rule_info = $eval;
            } else {
                $message_status = "Security log successfully ingested into SIEM database (ID: #$inserted_id).";
                $message_type = "alert-success";
            }
        } else {
            $message_status = "Error ingesting log: " . $conn->error;
            $message_type = "alert-error";
        }
    } else {
        $message_status = "Please complete all required fields.";
        $message_type = "alert-error";
    }
}

include "header.php";
?>

<div class="container">
    <div class="page-title-bar">
        <div>
            <h2>Ingest Security Event Log</h2>
            <p class="subtitle">Collect, normalize, and correlate raw syslog / event payloads through the SIEM rule engine</p>
        </div>
        <div>
            <a href="logs.php" class="btn btn-secondary">&larr; Back to Logs</a>
        </div>
    </div>

    <?php if (!empty($message_status)): ?>
        <div class="alert-box <?php echo $message_type; ?>">
            <span><?php echo $message_status; ?></span>
            <?php if ($triggered_rule_info): ?>
                <a href="alerts.php" class="btn btn-danger btn-sm" style="margin-left: 12px;">View in Alert Queue &rarr;</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- Attack Payload Quick-Fill Buttons -->
    <div class="panel" style="margin-bottom: 20px;">
        <h3 style="font-size: 14px; margin-bottom: 10px; color: var(--ms-blue);">Quick Attack / Event Payload Presets:</h3>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
            <button type="button" class="btn btn-secondary btn-sm" onclick="loadAttackTemplate('sqli')">🔴 SQL Injection Payload</button>
            <button type="button" class="btn btn-secondary btn-sm" onclick="loadAttackTemplate('bruteforce')">🟠 SSH Brute Force</button>
            <button type="button" class="btn btn-secondary btn-sm" onclick="loadAttackTemplate('portscan')">🟡 TCP Port Scanning</button>
            <button type="button" class="btn btn-secondary btn-sm" onclick="loadAttackTemplate('xss')">🔵 Cross-Site Scripting (XSS)</button>
            <button type="button" class="btn btn-secondary btn-sm" onclick="loadAttackTemplate('privilege')">🔴 Sudo Escalation</button>
            <button type="button" class="btn btn-secondary btn-sm" onclick="loadAttackTemplate('benign')">🟢 Benign User Login</button>
        </div>
    </div>

    <div class="panel">
        <form method="POST" action="add_log.php" onsubmit="return validateLogForm()">
            <div class="form-row">
                <div class="form-group">
                    <label for="source_ip">Source IP (Attacker / Client) *</label>
                    <input type="text" id="source_ip" name="source_ip" placeholder="e.g. 192.168.1.50" required>
                </div>

                <div class="form-group">
                    <label for="dest_ip">Destination IP (Target / Server) *</label>
                    <input type="text" id="dest_ip" name="dest_ip" value="192.168.1.100" required>
                </div>

                <div class="form-group">
                    <label for="port">Destination Port *</label>
                    <input type="number" id="port" name="port" value="80" min="1" max="65535" required>
                </div>

                <div class="form-group">
                    <label for="protocol">Protocol</label>
                    <select id="protocol" name="protocol">
                        <option value="HTTP">HTTP</option>
                        <option value="HTTPS">HTTPS</option>
                        <option value="SSH">SSH</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="DNS">DNS</option>
                        <option value="FTP">FTP</option>
                    </select>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label for="event_type">Event Category / Type</label>
                    <select id="event_type" name="event_type">
                        <option value="Web Attack">Web Attack</option>
                        <option value="Brute Force">Brute Force</option>
                        <option value="Port Scan">Port Scan</option>
                        <option value="Privilege Escalation">Privilege Escalation</option>
                        <option value="Malware Activity">Malware Activity</option>
                        <option value="Auth Success">Auth Success</option>
                        <option value="Auth Failure">Auth Failure</option>
                        <option value="DNS Query">DNS Query</option>
                        <option value="System Event">System Event</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="severity">Reported Severity</label>
                    <select id="severity" name="severity">
                        <option value="INFO">INFO</option>
                        <option value="LOW">LOW</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="HIGH">HIGH</option>
                        <option value="CRITICAL">CRITICAL</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="username">Target User / Account</label>
                    <input type="text" id="username" name="username" placeholder="e.g. root, admin, guest, anonymous" value="anonymous">
                </div>

                <div class="form-group">
                    <label for="action_taken">Initial Action Taken</label>
                    <select id="action_taken" name="action_taken">
                        <option value="Logged">Logged</option>
                        <option value="Allowed">Allowed</option>
                        <option value="Blocked">Blocked</option>
                        <option value="Flagged">Flagged</option>
                        <option value="Terminated">Terminated</option>
                    </select>
                </div>
            </div>

            <div class="form-group">
                <label for="message">Raw Log Message / Payload Signature *</label>
                <textarea id="message" name="message" rows="4" placeholder="Enter log details or payload text (e.g. GET /login.php?id=1 UNION SELECT ...)" required></textarea>
                <small style="color: var(--text-muted); font-size: 12px;">
                    💡 The SIEM engine will scan this text against active detection rules (e.g. "UNION SELECT", "Failed login", "Port scan", "sudo su unauthorized").
                </small>
            </div>

            <div style="display: flex; gap: 12px; margin-top: 20px;">
                <button type="submit" class="btn btn-primary">&plus; Ingest Log & Evaluate Rules</button>
                <button type="reset" class="btn btn-secondary">Clear Form</button>
            </div>
        </form>
    </div>
</div>

<?php include "footer.php"; ?>
