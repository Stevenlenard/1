<?php
/**
 * DEBUG: Session & Auth Status Checker
 * Shows current session state and database auth_sessions records
 */

require_once 'includes/config.php';

// Get current session info
$session_active = isLoggedIn();
$is_admin = isAdmin();
$is_janitor = isJanitor();
$current_user_id = getCurrentUserId();
$current_user_type = getCurrentUserType();

// Get auth_sessions from database
$auth_records = [];
$auth_cookie = $_COOKIE['auth_token'] ?? null;

if ($pdo) {
    try {
        $stmt = $pdo->query("
            SELECT 
                session_id,
                user_type,
                user_id,
                is_active,
                expires_at,
                created_at,
                last_activity
            FROM auth_sessions
            ORDER BY created_at DESC
            LIMIT 20
        ");
        $auth_records = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>Session Debug Info</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h2 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .info { margin: 15px 0; padding: 10px; background: #e7f3ff; border-left: 4px solid #007bff; }
        .success { background: #d4edda; border-left-color: #28a745; }
        .error { background: #f8d7da; border-left-color: #dc3545; }
        .warning { background: #fff3cd; border-left-color: #ffc107; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        table, th, td { border: 1px solid #ddd; }
        th { background: #007bff; color: white; padding: 10px; }
        td { padding: 10px; }
        tr:nth-child(even) { background: #f9f9f9; }
        .active { color: #28a745; font-weight: bold; }
        .inactive { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Session & Authentication Debug</h1>
        
        <h2>Current Session Status</h2>
        <div class="info <?php echo $session_active ? 'success' : 'error'; ?>">
            <strong>Session Active:</strong> <?php echo $session_active ? 'YES ✅' : 'NO ❌'; ?>
        </div>
        
        <?php if ($session_active): ?>
            <div class="info success">
                <strong>User Type:</strong> <?php echo strtoupper($current_user_type); ?><br>
                <strong>User ID:</strong> <?php echo $current_user_id; ?><br>
                <strong>Is Admin:</strong> <?php echo $is_admin ? 'YES' : 'NO'; ?><br>
                <strong>Is Janitor:</strong> <?php echo $is_janitor ? 'YES' : 'NO'; ?>
            </div>
        <?php endif; ?>
        
        <h2>Cookies</h2>
        <div class="info <?php echo $auth_cookie ? 'success' : 'warning'; ?>">
            <strong>auth_token present:</strong> <?php echo $auth_cookie ? 'YES ✅' : 'NO (not set)'; ?><br>
            <?php if ($auth_cookie): ?>
                <strong>Token length:</strong> <?php echo strlen($auth_cookie); ?> chars<br>
                <strong>Token preview:</strong> <?php echo substr($auth_cookie, 0, 20); ?>...
            <?php endif; ?>
        </div>
        
        <h2>Database Auth Sessions</h2>
        <?php if (!empty($auth_records)): ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>User Type</th>
                        <th>User ID</th>
                        <th>Active?</th>
                        <th>Created</th>
                        <th>Expires</th>
                        <th>Last Activity</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($auth_records as $record): ?>
                    <tr>
                        <td><?php echo $record['session_id']; ?></td>
                        <td><?php echo ucfirst($record['user_type']); ?></td>
                        <td><?php echo $record['user_id']; ?></td>
                        <td class="<?php echo $record['is_active'] ? 'active' : 'inactive'; ?>">
                            <?php echo $record['is_active'] ? '1 (ACTIVE)' : '0 (INACTIVE)'; ?>
                        </td>
                        <td><?php echo $record['created_at']; ?></td>
                        <td><?php echo $record['expires_at']; ?></td>
                        <td><?php echo $record['last_activity']; ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <div class="info warning">
                No auth_sessions records found in database
            </div>
        <?php endif; ?>
        
        <h2>Expected Logout Flow</h2>
        <div class="info">
            <strong>1. User clicks Logout button on dashboard</strong><br>
            → Modal shows "Confirm Logout"<br>
            <br>
            <strong>2. User clicks "Yes, Logout"</strong><br>
            → confirmLogout() → logout-confirm.php<br>
            <br>
            <strong>3. logout-confirm.php executes:</strong><br>
            ✅ UPDATE auth_sessions SET is_active = 0 WHERE user_id = X<br>
            ✅ Destroys $_SESSION<br>
            ✅ Deletes auth_token cookie<br>
            ✅ Redirects to user-login.php<br>
            <br>
            <strong>4. User tries to login again</strong><br>
            → Goes to user-login.php<br>
            → config.php tries validateAndRestoreSession()<br>
            → Database query: WHERE token_hash = ? AND is_active = 1<br>
            → NO RESULT (is_active = 0)<br>
            → Returns false<br>
            → Login form SHOWS<br>
            <br>
            <strong>5. User fills login form</strong><br>
            → login-handler.php validates credentials<br>
            → createAuthSession() INSERT with is_active = 1 ✅<br>
            → NEW auth_token cookie set<br>
            → Redirects to janitor-dashboard.php with fresh session
        </div>
        
        <h2>How to Test</h2>
        <div class="info">
            <strong>Step 1:</strong> Login as Janitor (go to user-login.php)<br>
            <strong>Step 2:</strong> Go to janitor-dashboard.php<br>
            <strong>Step 3:</strong> Click Logout button<br>
            <strong>Step 4:</strong> Confirm logout in modal<br>
            <strong>Step 5:</strong> Check this page - should show NO session<br>
            <strong>Step 6:</strong> Try to go to janitor-dashboard.php<br>
            → Should redirect to user-login.php<br>
            <strong>Step 7:</strong> Try to login again<br>
            → Should show login form (not auto-redirect)<br>
            → Fill credentials<br>
            → Should go to dashboard with NEW session<br>
            <strong>Step 8:</strong> Check this page again<br>
            → Should show new session with is_active = 1
        </div>
        
        <hr>
        <p style="font-size: 12px; color: #999;">
            Last refreshed: <?php echo date('Y-m-d H:i:s'); ?><br>
            Reload this page to refresh data
        </p>
    </div>
</body>
</html>
