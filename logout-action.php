<?php
// logout-action.php
// Deactivate the current auth token (set is_active = 0), destroy PHP session and clear cookies.

require __DIR__ . '/includes/config.php';

header('Content-Type: application/json');

$result = ['success' => false, 'message' => ''];

// Try deactivate by auth_token cookie first (most precise)
if (!empty($_COOKIE['auth_token'])) {
    $token = $_COOKIE['auth_token'];
    $token_hash = hash('sha256', $token);
    try {
        $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0, last_activity = NOW() WHERE token_hash = ?");
        $stmt->execute([$token_hash]);
        $affected = $stmt->rowCount();
        if ($affected > 0) {
            $result['success'] = true;
            $result['message'] = 'Session deactivated';
        } else {
            // No row matched the token. Try to deactivate any sessions for logged-in user (fallback)
            if (!empty($_SESSION)) {
                if (!empty($_SESSION['admin_id'])) {
                    $stmt2 = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE user_type = 'admin' AND user_id = ?");
                    $stmt2->execute([$_SESSION['admin_id']]);
                    $result['success'] = true;
                    $result['message'] = 'No token match; deactivated by session admin_id fallback';
                } elseif (!empty($_SESSION['janitor_id'])) {
                    $stmt2 = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE user_type = 'janitor' AND user_id = ?");
                    $stmt2->execute([$_SESSION['janitor_id']]);
                    $result['success'] = true;
                    $result['message'] = 'No token match; deactivated by session janitor_id fallback';
                }
            }
        }
    } catch (Exception $e) {
        $result['message'] = 'DB error: ' . $e->getMessage();
    }
} else {
    // No auth_token cookie - attempt to use session user id
    if (!empty($_SESSION)) {
        try {
            if (!empty($_SESSION['admin_id'])) {
                $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE user_type = 'admin' AND user_id = ?");
                $stmt->execute([$_SESSION['admin_id']]);
                $result['success'] = true;
                $result['message'] = 'Deactivated by admin_id session';
            } elseif (!empty($_SESSION['janitor_id'])) {
                $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE user_type = 'janitor' AND user_id = ?");
                $stmt->execute([$_SESSION['janitor_id']]);
                $result['success'] = true;
                $result['message'] = 'Deactivated by janitor_id session';
            } else {
                $result['message'] = 'No session identifiers found';
            }
        } catch (Exception $e) {
            $result['message'] = 'DB error: ' . $e->getMessage();
        }
    } else {
        $result['message'] = 'No auth_token cookie and no active PHP session';
    }
}

// Clear PHP session server-side
if (session_status() === PHP_SESSION_ACTIVE) {
    $_SESSION = [];
    @session_unset();
    @session_destroy();
}

// Clear cookies - make sure path matches how cookies were set (root '/')
if (isset($_COOKIE['auth_token'])) {
    setcookie('auth_token', '', time() - 3600, '/');
    unset($_COOKIE['auth_token']);
}
// Clear PHPSESSID cookie as well
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
    unset($_COOKIE[session_name()]);
}

echo json_encode($result);

exit;
