<?php
session_start();
include "db.php";

$page_title = "SOC Analyst Login";
$active_nav = "login";
$error = "";

if (isset($_SESSION["username"])) {
    header("Location: dashboard.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $password = trim($_POST["password"] ?? "");

    if (!empty($username) && !empty($password)) {
        $stmt = $conn->prepare("SELECT id, username, password, full_name, role FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result && $result->num_rows === 1) {
            $user = $result->fetch_assoc();
            if ($password === $user["password"] || password_verify($password, $user["password"])) {
                $_SESSION["user_id"] = $user["id"];
                $_SESSION["username"] = $user["username"];
                $_SESSION["full_name"] = $user["full_name"];
                $_SESSION["role"] = $user["role"];

                header("Location: dashboard.php");
                exit();
            } else {
                $error = "Invalid password. Default password is: admin123";
            }
        } else {
            $error = "User not found. Default username is: admin";
        }
    } else {
        $error = "Please fill in all credentials.";
    }
}

include "header.php";
?>

<div class="container">
    <div class="login-card">
        <h2>SOC Analyst Login</h2>
        <p class="subtitle">Enter your credentials to access the SIEM Control Dashboard</p>

        <?php if (!empty($error)): ?>
            <div class="alert-box alert-error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php" onsubmit="return validateLogin()">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="e.g. admin" required autofocus>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="e.g. admin123" required>
            </div>

            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 10px;">
                Authenticate to SOC &rarr;
            </button>
        </form>

        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-light); font-size: 13px; color: var(--text-secondary); text-align: center;">
            <p>Need a new analyst account? <a href="register.php" style="color: var(--ms-blue); font-weight: 600; text-decoration: none;">Register here</a></p>
            <p style="margin-top: 10px; font-size: 12px; color: var(--text-muted);">Default Admin: <code class="code-pill">admin</code> | <code class="code-pill">admin123</code></p>
        </div>
    </div>
</div>

<?php include "footer.php"; ?>
