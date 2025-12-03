<?php
/**
 * LOGOUT - Set is_active = 0
 * Complete session termination:
 * 1. Database: Set is_active = 0 (inactive)
 * 2. PHP session: Destroy
 * 3. Cookies: Delete all
 * Result: Next login shows form + fresh session
 */

// Get DB credentials
$db_host = getenv('DB_HOST') ?: '127.0.0.1';
$db_user = getenv('DB_USER') ?: 'root';
$db_pass = getenv('DB_PASS') ?: '';
$db_name = getenv('DB_NAME') ?: 'trashbin_management';

// Start session to get user info
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$user_id = $_SESSION['admin_id'] ?? $_SESSION['janitor_id'] ?? null;
$user_type = isset($_SESSION['admin_id']) ? 'admin' : (isset($_SESSION['janitor_id']) ? 'janitor' : null);

error_log("[LOGOUT] User {$user_type} ID {$user_id} logging out");

// Connect to DB
try {
    $pdo = new PDO(
        "mysql:host={$db_host};dbname={$db_name};charset=utf8mb4",
        $db_user,
        $db_pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (Exception $e) {
    error_log("[LOGOUT] DB error: " . $e->getMessage());
    $pdo = null;
}

// STEP 1: Set is_active = 0 for this user's sessions
if ($user_id && $user_type && $pdo) {
    try {
        $stmt = $pdo->prepare("
            UPDATE auth_sessions 
            SET is_active = 0 
            WHERE user_id = ? AND user_type = ?
        ");
        $stmt->execute([$user_id, $user_type]);
        error_log("[LOGOUT] Set is_active=0 for sessions");
    } catch (Exception $e) {
        error_log("[LOGOUT] DB update error: " . $e->getMessage());
    }
}

// STEP 2: Destroy PHP session
$_SESSION = [];
session_destroy();
error_log("[LOGOUT] PHP session destroyed");

// STEP 3: Delete cookies
setcookie('auth_token', '', time() - 3600, '/');
setcookie('auth_token', '', time() - 3600, '/', '', true, true);
setcookie('PHPSESSID', '', time() - 3600, '/');
unset($_COOKIE['auth_token']);
error_log("[LOGOUT] Cookies deleted");

// STEP 4: No-cache headers
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// STEP 5: Redirect to index
error_log("[LOGOUT] Complete - redirecting to index.php");
header('Location: index.php');
exit();
?>
