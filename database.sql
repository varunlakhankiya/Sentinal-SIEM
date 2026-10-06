-- SIEM (Security Information & Event Management) Database Schema
-- Database Name: simple_siem_db

CREATE DATABASE IF NOT EXISTS simple_siem_db;
USE simple_siem_db;

-- 1. Users / SOC Analysts Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) DEFAULT 'SOC Analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Detection Rules Table
CREATE TABLE IF NOT EXISTS detection_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    pattern_keyword VARCHAR(100) NOT NULL,
    description TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Security Event Logs Table
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity ENUM('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'INFO',
    username VARCHAR(50) DEFAULT 'system',
    message TEXT NOT NULL,
    action_taken VARCHAR(50) DEFAULT 'Logged',
    rule_triggered VARCHAR(100) DEFAULT NULL
);

-- 4. Alerts & Incidents Table
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    title VARCHAR(150) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    category VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    log_id INT NULL,
    status ENUM('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') DEFAULT 'OPEN',
    assigned_to VARCHAR(50) DEFAULT 'Unassigned',
    analyst_notes TEXT,
    FOREIGN KEY (log_id) REFERENCES security_logs(id) ON DELETE SET NULL
);

-- Default Analyst / Admin User
INSERT INTO users (username, password, full_name, role)
VALUES ('admin', 'admin123', 'Varun Lakhankiya', 'SOC Lead')
ON DUPLICATE KEY UPDATE full_name='Varun Lakhankiya';

-- Pre-configured SIEM Detection Rules
INSERT INTO detection_rules (rule_name, category, severity, pattern_keyword, description, is_active)
VALUES
('SQL Injection Attempt', 'Web Application', 'CRITICAL', 'UNION SELECT', 'Detects SQL injection signatures in HTTP query payloads', 1),
('Brute Force Authentication', 'Authentication', 'HIGH', 'Failed login', 'Detects multiple consecutive failed authentication attempts', 1),
('Port Scanning Activity', 'Reconnaissance', 'MEDIUM', 'Port scan detected', 'Detects rapid multi-port TCP SYN probes across network perimeter', 1),
('Unauthorized Root Access', 'Privilege Escalation', 'CRITICAL', 'sudo su unauthorized', 'Detects unauthorized privilege escalation to superuser', 1),
('Malware C2 Beaconing', 'Malware', 'HIGH', 'Tor exit node', 'Detects outbound connections to known malicious Command & Control IPs', 1),
('Cross-Site Scripting (XSS)', 'Web Application', 'MEDIUM', '<script>', 'Detects unencoded JavaScript injection in web inputs', 1)
ON DUPLICATE KEY UPDATE rule_name=rule_name;

-- Sample Telemetry / Initial Logs
INSERT INTO security_logs (timestamp, source_ip, dest_ip, port, protocol, event_type, severity, username, message, action_taken, rule_triggered)
VALUES
(NOW() - INTERVAL 12 MINUTE, '192.168.1.45', '192.168.1.1', 443, 'HTTPS', 'Auth Success', 'INFO', 'alice', 'User alice logged into portal successfully.', 'Allowed', NULL),
(NOW() - INTERVAL 10 MINUTE, '185.220.101.5', '192.168.1.100', 80, 'HTTP', 'Web Attack', 'CRITICAL', 'anonymous', 'GET /login.php?id=1 UNION SELECT username,password FROM users', 'Blocked', 'SQL Injection Attempt'),
(NOW() - INTERVAL 8 MINUTE, '198.51.100.23', '192.168.1.22', 22, 'SSH', 'Brute Force', 'HIGH', 'root', 'Failed login attempt for user root from 198.51.100.23 (Attempt 5/5)', 'Flagged', 'Brute Force Authentication'),
(NOW() - INTERVAL 6 MINUTE, '10.0.0.15', '10.0.0.1', 53, 'DNS', 'DNS Query', 'INFO', 'system', 'Standard DNS query resolved for internal directory.', 'Allowed', NULL),
(NOW() - INTERVAL 4 MINUTE, '203.0.113.44', '192.168.1.1', 8080, 'TCP', 'Port Scan', 'MEDIUM', 'unknown', 'Port scan detected: sequential SYN probe on ports 21, 22, 23, 80, 443, 8080', 'Alerted', 'Port Scanning Activity'),
(NOW() - INTERVAL 2 MINUTE, '192.168.1.110', '192.168.1.5', 22, 'SSH', 'Privilege Escalation', 'CRITICAL', 'guest', 'sudo su unauthorized attempt by non-wheel user guest', 'Blocked', 'Unauthorized Root Access');

-- Initial Alerts generated from above logs
INSERT INTO alerts (timestamp, title, severity, category, source_ip, log_id, status, assigned_to, analyst_notes)
VALUES
(NOW() - INTERVAL 10 MINUTE, 'SQL Injection in Login Endpoint', 'CRITICAL', 'Web Application', '185.220.101.5', 2, 'OPEN', 'Unassigned', 'WAF intercepted malicious query parameter. IP added to temporary watchlist.'),
(NOW() - INTERVAL 8 MINUTE, 'SSH Brute Force on Gateway Server', 'HIGH', 'Authentication', '198.51.100.23', 3, 'IN_PROGRESS', 'admin', 'Rate limiting triggered. Investigating origin ASN.'),
(NOW() - INTERVAL 4 MINUTE, 'Perimeter Port Scan Detected', 'MEDIUM', 'Reconnaissance', '203.0.113.44', 5, 'OPEN', 'Unassigned', 'Network firewall logged probe sweep from external IP.'),
(NOW() - INTERVAL 2 MINUTE, 'Unauthorized Sudo Escalation Attempt', 'CRITICAL', 'Privilege Escalation', '192.168.1.110', 6, 'OPEN', 'Unassigned', 'Internal host 192.168.1.110 attempted root privilege escalation.');
