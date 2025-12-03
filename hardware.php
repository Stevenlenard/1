<?php
require_once 'includes/config.php';

if (isset($_GET['bin_id'], $_GET['status'], $_GET['capacity'])) {

    $bin_id = intval($_GET['bin_id']);
    $status = $_GET['status'];
    $capacity = floatval($_GET['capacity']);

    $allowed = ['empty','half_full','full'];

    if (!in_array($status, $allowed)) {
        echo json_encode(['success'=>false,'message'=>'Invalid status']);
        exit;
    }

    // 1️⃣ Update the bin table
    $stmt = $conn->prepare("UPDATE bins SET status=?, capacity=?, updated_at=NOW() WHERE bin_id=?");
    $stmt->bind_param("sdi", $status, $capacity, $bin_id);
    $success = $stmt->execute();
    $stmt->close();

    // 2️⃣ If status is FULL, insert a notification
    if ($status === 'full') {
        // Prevent duplicate notifications
        $check = $conn->prepare("SELECT COUNT(*) AS c FROM notifications WHERE bin_id=? AND notification_type='critical' AND is_read=0");
        $check->bind_param("i", $bin_id);
        $check->execute();
        $row = $check->get_result()->fetch_assoc();
        $check->close();

        if (intval($row['c'] ?? 0) === 0) {
            $title = "Bin Full Alert";
            $message = "Bin ID $bin_id is full. Immediate attention required!";

            $notif = $conn->prepare("INSERT INTO notifications (bin_id, notification_type, title, message, created_at) VALUES (?, 'critical', ?, ?, NOW())");
            $notif->bind_param("iss", $bin_id, $title, $message);
            $notif->execute();
            $notif->close();
        }
    }

    echo json_encode(['success'=>$success]);
    exit;
}

echo json_encode(['success'=>false,'message'=>'Missing parameters']);
