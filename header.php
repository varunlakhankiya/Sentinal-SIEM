<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
// Default current page if not set
if (!isset($page_title)) {
    $page_title = "Sentinel SIEM";
}
if (!isset($active_nav)) {
    $active_nav = "";
}

$is_logged_in = isset($_SESSION["username"]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?> - Sentinel SIEM</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<header>
    <div class="header-inner">
        <a href="<?php echo $is_logged_in ? 'dashboard.php' : 'login.php'; ?>" class="logo-area" style="text-decoration: none; color: inherit;">
            <div class="logo-badge">SIEM</div>
            <h1>Sentinel <span>SIEM</span></h1>
        </a>
        
        <nav>
            <?php if ($is_logged_in): ?>
                <!-- Authenticated SOC Navigation Links Only -->
                <a href="dashboard.php" class="<?php echo ($active_nav === 'dashboard') ? 'active' : ''; ?>">Dashboard</a>
                <a href="logs.php" class="<?php echo ($active_nav === 'logs') ? 'active' : ''; ?>">Event Logs</a>
                <a href="add_log.php" class="<?php echo ($active_nav === 'add_log') ? 'active' : ''; ?>">Ingest Log</a>
                <a href="alerts.php" class="<?php echo ($active_nav === 'alerts') ? 'active' : ''; ?>">Incidents</a>
                <a href="rules.php" class="<?php echo ($active_nav === 'rules') ? 'active' : ''; ?>">Rules</a>
                <a href="simulator.php" class="<?php echo ($active_nav === 'simulator') ? 'active' : ''; ?>">Simulator</a>
                <a href="logout.php" class="btn btn-logout btn-sm">Logout (<?php echo htmlspecialchars($_SESSION["username"]); ?>)</a>
            <?php endif; ?>
        </nav>
    </div>
</header>
