<?php
session_start();

if (!isset($_SESSION["username"])) {
    header("Location: login.php");
    exit();
}

include "db.php";

$page_title = "Rules Engine";
$active_nav = "rules";

$msg = "";
$msg_type = "alert-info";

// Toggle rule active status
if (isset($_GET['toggle_id'])) {
    $toggle_id = intval($_GET['toggle_id']);
    $conn->query("UPDATE detection_rules SET is_active = IF(is_active=1, 0, 1) WHERE id = $toggle_id");
    header("Location: rules.php?msg=toggled");
    exit();
}

// Delete rule
if (isset($_GET['delete_rule_id'])) {
    $del_id = intval($_GET['delete_rule_id']);
    $conn->query("DELETE FROM detection_rules WHERE id = $del_id");
    header("Location: rules.php?msg=deleted");
    exit();
}

// Add new detection rule
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["add_rule"])) {
    $rule_name = trim($_POST["rule_name"] ?? "");
    $category = trim($_POST["category"] ?? "General");
    $severity = trim($_POST["severity"] ?? "MEDIUM");
    $pattern = trim($_POST["pattern_keyword"] ?? "");
    $description = trim($_POST["description"] ?? "");

    if (!empty($rule_name) && !empty($pattern)) {
        $stmt = $conn->prepare("INSERT INTO detection_rules (rule_name, category, severity, pattern_keyword, description, is_active) VALUES (?, ?, ?, ?, ?, 1)");
        $stmt->bind_param("sssss", $rule_name, $category, $severity, $pattern, $description);
        if ($stmt->execute()) {
            $msg = "New SIEM correlation rule '$rule_name' deployed successfully!";
            $msg_type = "alert-success";
        } else {
            $msg = "Error deploying rule: " . $conn->error;
            $msg_type = "alert-error";
        }
    } else {
        $msg = "Please provide Rule Name and Pattern Keyword.";
        $msg_type = "alert-error";
    }
}

$rules = $conn->query("SELECT * FROM detection_rules ORDER BY id ASC");

include "header.php";
?>

<div class="container">
    <div class="page-title-bar">
        <div>
            <h2>SIEM Threat Detection & Correlation Rules</h2>
            <p class="subtitle">Define pattern signatures, correlation thresholds, and automated incident generation triggers</p>
        </div>
        <div>
            <a href="simulator.php" class="btn btn-cyan">Test Rules with Simulator</a>
        </div>
    </div>

    <?php if (isset($_GET['msg']) && $_GET['msg'] === 'toggled'): ?>
        <div class="alert-box alert-success">&check; Rule status updated!</div>
    <?php elseif (isset($_GET['msg']) && $_GET['msg'] === 'deleted'): ?>
        <div class="alert-box alert-info">&check; Detection rule removed.</div>
    <?php elseif (!empty($msg)): ?>
        <div class="alert-box <?php echo $msg_type; ?>"><?php echo htmlspecialchars($msg); ?></div>
    <?php endif; ?>

    <!-- Active Rules Table -->
    <div class="panel">
        <div class="panel-header">
            <h3>Active Detection Signature Rules</h3>
        </div>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Rule Name</th>
                        <th>Category</th>
                        <th>Severity</th>
                        <th>Payload Signature / Pattern</th>
                        <th>Description</th>
                        <th>Status</th>
                        <th>Toggle / Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($rules && $rules->num_rows > 0): ?>
                        <?php while ($r = $rules->fetch_assoc()): ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($r['rule_name']); ?></strong></td>
                                <td><?php echo htmlspecialchars($r['category']); ?></td>
                                <td>
                                    <span class="badge badge-<?php echo strtolower($r['severity']); ?>">
                                        <?php echo htmlspecialchars($r['severity']); ?>
                                    </span>
                                </td>
                                <td><code class="code-pill"><?php echo htmlspecialchars($r['pattern_keyword']); ?></code></td>
                                <td style="font-size: 13px; color: var(--text-secondary);"><?php echo htmlspecialchars($r['description']); ?></td>
                                <td>
                                    <?php if ($r['is_active']): ?>
                                        <span class="badge badge-status-resolved">ACTIVE</span>
                                    <?php else: ?>
                                        <span class="badge badge-status-false_positive">DISABLED</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <a href="rules.php?toggle_id=<?php echo $r['id']; ?>" class="btn btn-secondary btn-sm">
                                        <?php echo $r['is_active'] ? 'Disable' : 'Enable'; ?>
                                    </a>
                                    <a href="rules.php?delete_rule_id=<?php echo $r['id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Delete this rule?')" style="margin-left: 4px;">Delete</a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr><td colspan="7" style="text-align: center;">No rules configured.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Create New Correlation Rule -->
    <div class="panel">
        <div class="panel-header">
            <h3>+ Create Custom Detection Rule</h3>
        </div>
        <form method="POST" action="rules.php">
            <input type="hidden" name="add_rule" value="1">
            <div class="form-row">
                <div class="form-group">
                    <label for="rule_name">Rule Name *</label>
                    <input type="text" id="rule_name" name="rule_name" placeholder="e.g. Directory Traversal Attack" required>
                </div>

                <div class="form-group">
                    <label for="category">Threat Category</label>
                    <select id="category" name="category">
                        <option value="Web Application">Web Application</option>
                        <option value="Authentication">Authentication</option>
                        <option value="Reconnaissance">Reconnaissance</option>
                        <option value="Privilege Escalation">Privilege Escalation</option>
                        <option value="Malware">Malware</option>
                        <option value="Network">Network</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="severity">Alert Severity</label>
                    <select id="severity" name="severity">
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM" selected>MEDIUM</option>
                        <option value="LOW">LOW</option>
                    </select>
                </div>
            </div>

            <div class="form-group">
                <label for="pattern_keyword">Trigger Pattern / Keyword Signature *</label>
                <input type="text" id="pattern_keyword" name="pattern_keyword" placeholder="e.g. ../../etc/passwd or cmd.exe or /wp-admin" required>
                <small style="color: var(--text-secondary); font-size: 12px;">When any ingested log contains this string, the SIEM will automatically trigger this rule and raise an Incident Alert.</small>
            </div>

            <div class="form-group">
                <label for="description">Rule Description & SOC Mitigation Guidance</label>
                <textarea id="description" name="description" rows="2" placeholder="Explain what this attack represents and what the SOC analyst should do."></textarea>
            </div>

            <button type="submit" class="btn btn-primary">&plus; Deploy Correlation Rule</button>
        </form>
    </div>
</div>

<?php include "footer.php"; ?>
