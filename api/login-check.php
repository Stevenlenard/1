<?php
/**
 * LOGIN CHECK - Separate file to verify if user is logged in
 * Returns JSON: {logged_in: true/false, role: 'admin'|'janitor'|null}
 * Does NOT auto-restore sessions
 */

// NO config.php - start fresh
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check current session ONLY (no auto-restore)
$logged_in = false;
$role = null;

if (isset($_SESSION['admin_id'])) {
    $logged_in = true;
    $role = 'admin';
} elseif (isset($_SESSION['janitor_id'])) {
    $logged_in = true;
    $role = 'janitor';
}

header('Content-Type: application/json');
echo json_encode([
    'logged_in' => $logged_in,
    'role' => $role
]);
exit;
?>
