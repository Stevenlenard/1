<?php
/**
 * Clean standalone logout handler
 * Sets is_active = 0 in auth_sessions, destroys PHP session, clears cookies
 * Returns JSON success/fail
 */

session_start();
require_once __DIR__ . '/../includes/config.php';

header('Content-Type: application/json');

$result = ['success' => false, 'message' => ''];

try {
    // Get the token from the cookie
    $token = $_COOKIE['auth_token'] ?? null;
    
    if (!$token) {
        // No token cookie - try to logout using session user ID
        if (!empty($_SESSION['admin_id'])) {
            $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE user_type = 'admin' AND user_id = ?");
            $stmt->execute([$_SESSION['admin_id']]);
            $result['success'] = true;
        } elseif (!empty($_SESSION['janitor_id'])) {
            $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE user_type = 'janitor' AND user_id = ?");
            $stmt->execute([$_SESSION['janitor_id']]);
            $result['success'] = true;
        }
    } else {
        // Hash the token and find the matching session
        $token_hash = hash('sha256', $token);
        $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE token_hash = ?");
        $stmt->execute([$token_hash]);
        if ($stmt->rowCount() > 0) {
            $result['success'] = true;
        }
    }
    
    // Clear PHP session
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        @session_unset();
        @session_destroy();
    }
    
    // Clear cookies
    setcookie('auth_token', '', time() - 3600, '/');
    setcookie(session_name(), '', time() - 3600, '/');
    unset($_COOKIE['auth_token']);
    unset($_COOKIE[session_name()]);
    
    $result['message'] = $result['success'] ? 'Logged out successfully' : 'Logout completed';
    
} catch (Exception $e) {
    $result['success'] = false;
    $result['message'] = 'Error: ' . $e->getMessage();
}

echo json_encode($result);
exit;
?>
