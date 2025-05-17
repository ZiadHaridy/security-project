<?php
session_start();
require 'db.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Invalid CSRF token");
    }

    $name = trim($_POST['Name']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $cpassword = $_POST['cpassword'];

    if (strlen($name) < 3 || strlen($password) < 5) {
        die("Invalid name or password length.");
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format.");
    }

    if ($password !== $cpassword) {
        die("Passwords do not match.");
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    if ($stmt->fetchColumn() > 0) {
        die("Email is already registered.");
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare("INSERT INTO users (name, email, password) VALUES (:name, :email, :password)");
    $stmt->execute([
        'name' => htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
        'email' => $email,
        'password' => $hashedPassword
    ]);

    echo "Registration successful! <a href='login.php'>Login now</a>";
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <link rel="stylesheet" href="./css/login"> <!-- Optional -->
</head>
<body>
    <div class="center">
        <h1>REGISTER</h1>
        <form method="post" action="SignUp.php">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="txt_field">
                <input type="text" name="Name" minlength="3" required>
                <label>Name</label>
            </div>
            <div class="txt_field">
                <input type="text" name="email" required>
                <label>Email</label>
            </div>
            <div class="txt_field">
                <input type="password" name="password" minlength="5" required>
                <label>Password</label>
            </div>
            <div class="txt_field">
                <input type="password" name="cpassword" minlength="5" required>
                <label>Confirm Password</label>
            </div>
            <input type="submit" value="Register">
            <div class="signup_link">
                Already a member? <a href="login.php">Login</a>
            </div>
        </form>
    </div>
</body>
</html>
