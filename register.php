<?php
session_start();
include "db.php";

$page_title = "Analyst Registration";
$active_nav = "register";
$error = "";
$success = "";

if (isset($_SESSION["username"])) {
    header("Location: dashboard.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $full_name        = trim($_POST["full_name"] ?? "");
    $username         = trim($_POST["username"] ?? "");
    $role             = trim($_POST["role"] ?? "SOC Analyst");
    $password         = trim($_POST["password"] ?? "");
    $confirm_password = trim($_POST["confirm_password"] ?? "");

    if (empty($full_name) || empty($username) || empty($password)) {
        $error = "Please fill in all required fields.";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match. Please try again.";
    } elseif (strlen($password) < 4) {
        $error = "Password must be at least 4 characters long.";
    } else {
        // Check if username already exists
        $check_stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $check_stmt->bind_param("s", $username);
        $check_stmt->execute();
        $check_res = $check_stmt->get_result();

        if ($check_res && $check_res->num_rows > 0) {
            $error = "Username '$username' is already taken. Please choose another.";
        } else {
            // Insert new SOC analyst user
            $insert_stmt = $conn->prepare("INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, ?)");
            $insert_stmt->bind_param("ssss", $username, $password, $full_name, $role);

            if ($insert_stmt->execute()) {
                $success = "Registration successful! You can now log in to the SOC portal.";
            } else {
                $error = "Registration failed: " . $conn->error;
            }
        }
    }
}

include "header.php";
?>

<div class="container">
    <div class="login-card">
        <h2>SOC Analyst Registration</h2>
        <p class="subtitle">Create a new analyst profile to access SIEM telemetry</p>

        <?php if (!empty($error)): ?>
            <div class="alert-box alert-error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($success)): ?>
            <div class="alert-box alert-success">
                <div>
                    <?php echo htmlspecialchars($success); ?>
                    <div style="margin-top: 8px;">
                        <a href="login.php" class="btn btn-primary btn-sm">Proceed to Login &rarr;</a>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <form method="POST" action="register.php">
                <div class="form-group">
                    <label for="full_name">Full Name *</label>
                    <input type="text" id="full_name" name="full_name" placeholder="e.g. Varun Lakhankiya" value="<?php echo htmlspecialchars($_POST['full_name'] ?? ''); ?>" required autofocus>
                </div>

                <div class="form-group">
                    <label for="username">Analyst Username *</label>
                    <input type="text" id="username" name="username" placeholder="e.g. varun" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                </div>

                <div class="form-group">
                    <label for="role">Security Role</label>
                    <select id="role" name="role">
                        <option value="SOC Analyst" selected>SOC Analyst</option>
                        <option value="Security Engineer">Security Engineer</option>
                        <option value="Incident Responder">Incident Responder</option>
                        <option value="Threat Hunter">Threat Hunter</option>
                        <option value="SOC Lead">SOC Lead</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="password">Password *</label>
                    <input type="password" id="password" name="password" placeholder="Create a password" required>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm Password *</label>
                    <input type="password" id="confirm_password" name="confirm_password" placeholder="Re-enter your password" required>
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 10px;">
                    Register Analyst Profile &rarr;
                </button>
            </form>
        <?php endif; ?>

        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-light); font-size: 13px; color: var(--text-secondary); text-align: center;">
            <p>Already have an analyst account? <a href="login.php" style="color: var(--ms-blue); font-weight: 600; text-decoration: none;">Log in here</a></p>
        </div>
    </div>
</div>

<?php include "footer.php"; ?>
