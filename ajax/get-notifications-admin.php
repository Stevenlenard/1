<?php
require_once "../includes/config.php";

if (!isLoggedIn() || !isAdmin()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

$sql = "
    SELECT
        n.notification_id,
        n.admin_id,
        n.janitor_id,
        n.bin_id,
        n.notification_type,
        n.title,
        n.message,
        n.is_read,
        n.created_at,
        b.bin_code,
        CONCAT(j.first_name, ' ', j.last_name) AS janitor_name
    FROM notifications n
    LEFT JOIN bins b ON n.bin_id = b.bin_id
    LEFT JOIN janitors j ON n.janitor_id = j.janitor_id
    ORDER BY n.created_at DESC
    LIMIT 1000
";

$res = $conn->query($sql);
$data = [];

while ($row = $res->fetch_assoc()) {
    $data[] = $row;
}

echo json_encode([
    'success' => true,
    'notifications' => $data
]);
