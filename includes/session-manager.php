<?php
/**
 * Session Manager - Handles persistent authentication
 * Allows users to stay logged in across page reloads without explicit logout
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Generate a secure authentication token
 */
function generateAuthToken(): string {
    return bin2hex(random_bytes(32));
}

/**
 * Store session in database
 */
function createAuthSession($user_type, $user_id, $pdo): ?string {
    try {
        $token = generateAuthToken();
        $token_hash = hash('sha256', $token);
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $expires_at = date('Y-m-d H:i:s', time() + (30 * 24 * 60 * 60)); // 30 days

        $stmt = $pdo->prepare("
            INSERT INTO auth_sessions (user_type, user_id, token_hash, ip_address, user_agent, expires_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ");
        $stmt->execute([$user_type, $user_id, $token_hash, $ip_address, $user_agent, $expires_at]);

        return $token;
    } catch (Exception $e) {
        error_log("[session-manager] createAuthSession error: " . $e->getMessage());
        return null;
    }
}

/**
 * Validate and restore session from token cookie
 * Returns true if valid session found and restored, false otherwise
 */
function validateAndRestoreSession($pdo): bool {
    // Check if auth token exists in cookie
    $token = $_COOKIE['auth_token'] ?? null;
    if (!$token) {
        return false;
    }

    try {
        $token_hash = hash('sha256', $token);
        
        // Look up session in database - MUST be active
        $stmt = $pdo->prepare("
            SELECT user_type, user_id, expires_at, is_active 
            FROM auth_sessions 
            WHERE token_hash = ? AND is_active = 1
            LIMIT 1
        ");
        $stmt->execute([$token_hash]);
        $session_data = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$session_data) {
            // Token not found in database OR is_active = 0
            setcookie('auth_token', '', time() - 3600, '/');
            setcookie('auth_token', '', time() - 3600, '/', '', true, true);
            return false;
        }

        // Double-check if session is expired
        if (new DateTime($session_data['expires_at']) < new DateTime()) {
            // Session expired - deactivate it
            $deactivate = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE token_hash = ?");
            $deactivate->execute([$token_hash]);
            setcookie('auth_token', '', time() - 3600, '/');
            setcookie('auth_token', '', time() - 3600, '/', '', true, true);
            return false;
        }

        // Session is valid! Restore user to $_SESSION
        $user_type = $session_data['user_type'];
        $user_id = $session_data['user_id'];
        $table = $user_type === 'admin' ? 'admins' : 'janitors';
        $id_col = $user_type === 'admin' ? 'admin_id' : 'janitor_id';

        // Fetch user details
        $user_stmt = $pdo->prepare("
            SELECT {$id_col}, first_name, last_name, email, status 
            FROM {$table} 
            WHERE {$id_col} = ? AND status = 'active'
        ");
        $user_stmt->execute([$user_id]);
        $user = $user_stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            // User not found or inactive
            deactivateAuthSession($token_hash, $pdo);
            return false;
        }

        // Restore session
        if ($user_type === 'admin') {
            $_SESSION['admin_id'] = $user['admin_id'];
            $_SESSION['role'] = 'admin';
            $_SESSION['name'] = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
        } else {
            $_SESSION['janitor_id'] = $user['janitor_id'];
            $_SESSION['role'] = 'janitor';
            $_SESSION['name'] = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
        }

        // Update last activity
        $activity_stmt = $pdo->prepare("
            UPDATE auth_sessions 
            SET last_activity = NOW() 
            WHERE token_hash = ?
        ");
        $activity_stmt->execute([$token_hash]);

        // Refresh cookie expiry (extend it for another 30 days)
        setcookie('auth_token', $token, time() + (30 * 24 * 60 * 60), '/', '', true, true);

        return true;

    } catch (Exception $e) {
        error_log("[session-manager] validateAndRestoreSession error: " . $e->getMessage());
        return false;
    }
}

/**
 * Deactivate a session
 */
function deactivateAuthSession($token_hash, $pdo): bool {
    try {
        $stmt = $pdo->prepare("UPDATE auth_sessions SET is_active = 0 WHERE token_hash = ?");
        return $stmt->execute([$token_hash]);
    } catch (Exception $e) {
        error_log("[session-manager] deactivateAuthSession error: " . $e->getMessage());
        return false;
    }
}

/**
 * Logout - invalidate all user's sessions
 */
function logoutUser($pdo): void {
    $user_id = null;
    $user_type = null;

    if (isset($_SESSION['admin_id'])) {
        $user_id = $_SESSION['admin_id'];
        $user_type = 'admin';
    } elseif (isset($_SESSION['janitor_id'])) {
        $user_id = $_SESSION['janitor_id'];
        $user_type = 'janitor';
    }

    if ($user_id && $user_type) {
        try {
            // Deactivate all active sessions for this user
            $stmt = $pdo->prepare("
                UPDATE auth_sessions 
                SET is_active = 0 
                WHERE user_id = ? AND user_type = ? AND is_active = 1
            ");
            $stmt->execute([$user_id, $user_type]);
        } catch (Exception $e) {
            error_log("[session-manager] logoutUser error: " . $e->getMessage());
        }
    }

    // Clear session
    $_SESSION = [];
    session_destroy();

    // Clear auth token cookie
    setcookie('auth_token', '', time() - 3600, '/', '', true, true);
}

/**
 * Clean up expired sessions from database (run periodically)
 */
function cleanupExpiredSessions($pdo): int {
    try {
        $stmt = $pdo->prepare("
            DELETE FROM auth_sessions 
            WHERE expires_at < NOW() OR (is_active = 0 AND last_activity < DATE_SUB(NOW(), INTERVAL 7 DAY))
        ");
        $stmt->execute();
        return $stmt->rowCount();
    } catch (Exception $e) {
        error_log("[session-manager] cleanupExpiredSessions error: " . $e->getMessage());
        return 0;
    }
}

?>