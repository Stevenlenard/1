<?php
require_once __DIR__ . '/../includes/config.php';

header('Content-Type: application/json; charset=utf-8');

if (!isLoggedIn() || !isAdmin()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid report id']);
    exit;
}

try {
    // Prefer PDO if available
    if (isset($pdo) && $pdo instanceof PDO) {
        $stmt = $pdo->prepare("SELECT report_id, report_name, report_type, generated_by, date_from, date_to, report_data, format, status, file_path, created_at FROM reports WHERE report_id = ? LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
    } else {
        $stmt = $conn->prepare("SELECT report_id, report_name, report_type, generated_by, date_from, date_to, report_data, format, status, file_path, created_at FROM reports WHERE report_id = ? LIMIT 1");
        $stmt->bind_param('i', $id);
        $stmt->execute();
        $res = $stmt->get_result();
        $row = $res ? $res->fetch_assoc() : false;
    }

    if (!$row) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Report not found']);
        exit;
    }

    $row['report_data'] = $row['report_data'] ? json_decode($row['report_data'], true) : null;
    $file_exists = false;
    $download_url = null;
    if (!empty($row['file_path']) && file_exists(__DIR__ . '/../' . $row['file_path'])) {
        $file_exists = true;
        $download_url = '../download-report.php?id=' . urlencode($row['report_id']);
    }

    echo json_encode(['success' => true, 'report' => $row, 'file_exists' => $file_exists, 'download_url' => $download_url]);
    exit;
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server error']);
    error_log('[api/get-report] ' . $e->getMessage());
    exit;
}
