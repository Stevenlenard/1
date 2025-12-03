<?php
/**
 * NUCLEAR LOGOUT - Complete session wipe
 * No assumptions, no leftover data
 */

// Force start fresh session
session_write_close();
session_status() === PHP_SESSION_ACTIVE && session_destroy();

// Wait to ensure session is destroyed
usleep(100000);

// Start a new blank session ONLY to set cookies
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include only PDO for database cleanup
$db_host = getenv('DB_HOST') ?: '127.0.0.1';
$db_user = getenv('DB_USER') ?: 'root';
$db_pass = getenv('DB_PASS') ?: '';
$db_name = getenv('DB_NAME') ?: 'trashbin_management';
$db_charset = 'utf8mb4';

try {
    $pdo = new PDO(
        "mysql:host={$db_host};dbname={$db_name};charset={$db_charset}",
        $db_user,
        $db_pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    // Get user info from current session (if exists)
    $user_id = $_SESSION['admin_id'] ?? $_SESSION['janitor_id'] ?? null;
    $user_type = isset($_SESSION['admin_id']) ? 'admin' : (isset($_SESSION['janitor_id']) ? 'janitor' : null);

    // Deactivate ALL sessions for this user
    if ($user_id && $user_type) {
        $stmt = $pdo->prepare("
            UPDATE auth_sessions 
            SET is_active = 0 
            WHERE user_id = ? AND user_type = ? AND is_active = 1
        ");
        $stmt->execute([$user_id, $user_type]);
    }
} catch (Exception $e) {
    error_log("[logout] DB error: " . $e->getMessage());
}

// NUCLEAR SESSION CLEAR
$_SESSION = array();
session_destroy();

// NUCLEAR COOKIE CLEAR - multiple approaches to be safe
$cookie_options = [
    ['auth_token', '/', true, true],
    ['auth_token', '', true, true],
    ['PHPSESSID', '/', true, true],
    ['PHPSESSID', '', true, true],
];

foreach ($cookie_options as $options) {
    setcookie($options[0], '', time() - 99999999, $options[1], '', $options[2], $options[3]);
}

// Also clear any custom cookies
foreach ($_COOKIE as $key => $value) {
    setcookie($key, '', time() - 99999999, '/');
}

// Final check - make sure no session exists
@session_destroy();

// Redirect
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
header('Location: index.php?logout=true');
exit();
?>
