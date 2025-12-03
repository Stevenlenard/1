<?php
require_once 'includes/config.php';

// Check if user is logged in
if (!isLoggedIn()) {
    header('Location: user-login.php');
    exit;
}

// Check if user is janitor
if (!isJanitor()) {
    header('Location: admin-dashboard.php');
    exit;
}

// Determine janitor id from session
$janitorId = intval($_SESSION['janitor_id'] ?? $_SESSION['user_id'] ?? $_SESSION['id'] ?? 0);

/**
 * POST endpoint for janitors to update bin status.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'janitor_edit_status') {
    header('Content-Type: application/json; charset=utf-8');

    try {
        if (!$janitorId) throw new Exception('Unauthorized');

        $bin_id = intval($_POST['bin_id'] ?? 0);
        $status = trim($_POST['status'] ?? '');
        $actionType = trim($_POST['action_type'] ?? $_POST['actionType'] ?? '');

        // normalize legacy value
        if ($status === 'in_progress') $status = 'half_full';

        $valid_statuses = ['empty', 'half_full', 'full', 'needs_attention', 'disabled', 'out_of_service'];
        if (!in_array($status, $valid_statuses, true)) {
            throw new Exception('Invalid status value');
        }

        // map capacity where applicable
        $capacity_map = [
            'empty' => 10,
            'half_full' => 50,
            'full' => 90,
            'needs_attention' => null,
            'disabled' => null,
            'out_of_service' => null
        ];
        $capacity = $capacity_map[$status] ?? null;

        // Update bins table
        if ($capacity !== null) {
            $stmt = $conn->prepare("UPDATE bins SET status = ?, capacity = ?, updated_at = NOW() WHERE bin_id = ?");
            if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
            $stmt->bind_param("sii", $status, $capacity, $bin_id);
        } else {
            $stmt = $conn->prepare("UPDATE bins SET status = ?, updated_at = NOW() WHERE bin_id = ?");
            if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
            $stmt->bind_param("si", $status, $bin_id);
        }

        if (!$stmt->execute()) {
            $err = $stmt->error;
            $stmt->close();
            throw new Exception('Execute failed: ' . $err);
        }
        $affected = $stmt->affected_rows;
        $stmt->close();

        // Resolve janitor name
        $janitor_name = null;
        if ($janitorId > 0) {
            if (isset($pdo) && $pdo instanceof PDO) {
                try {
                    $aStmt = $pdo->prepare("SELECT first_name, last_name, phone, email FROM janitors WHERE janitor_id = ? LIMIT 1");
                    $aStmt->execute([(int)$janitorId]);
                    $aRow = $aStmt->fetch(PDO::FETCH_ASSOC);
                    if ($aRow) $janitor_name = trim(($aRow['first_name'] ?? '') . ' ' . ($aRow['last_name'] ?? ''));
                } catch (Exception $e) { /* ignore */ }
            } else {
                if ($stmtA = $conn->prepare("SELECT first_name, last_name, phone, email FROM janitors WHERE janitor_id = ? LIMIT 1")) {
                    $stmtA->bind_param("i", $janitorId);
                    $stmtA->execute();
                    $r2 = $stmtA->get_result()->fetch_assoc();
                    if ($r2) $janitor_name = trim(($r2['first_name'] ?? '') . ' ' . ($r2['last_name'] ?? ''));
                    $stmtA->close();
                }
            }
        }
        if (empty($janitor_name)) $janitor_name = $janitorId ? "Janitor #{$janitorId}" : 'A janitor';

        // Get bin code for message
        $bin_code = null;
        if ($bin_id > 0) {
            if (isset($pdo) && $pdo instanceof PDO) {
                try {
                    $bstmt = $pdo->prepare("SELECT bin_code FROM bins WHERE bin_id = ? LIMIT 1");
                    $bstmt->execute([(int)$bin_id]);
                    $brow = $bstmt->fetch(PDO::FETCH_ASSOC);
                    if ($brow) $bin_code = $brow['bin_code'] ?? null;
                } catch (Exception $e) { /* ignore */ }
            } else {
                $res = $conn->query("SELECT bin_code FROM bins WHERE bin_id = " . intval($bin_id) . " LIMIT 1");
                if ($res && $row = $res->fetch_assoc()) $bin_code = $row['bin_code'] ?? null;
            }
        }
        $binDisplay = $bin_code ? "Bin '{$bin_code}'" : "Bin #{$bin_id}";

        // Build notification message
        $notificationType = 'info';
        $statusText = ucfirst(str_replace('_', ' ', $status));
        $title = "{$binDisplay} status updated";
        $message = "{$janitor_name} updated status to \"{$statusText}\".";
        if (!empty($actionType)) $message .= " Action: {$actionType}.";

        // Insert notification
        try {
            if (isset($pdo) && $pdo instanceof PDO) {
                $stmtN = $pdo->prepare("
                    INSERT INTO notifications (admin_id, janitor_id, bin_id, notification_type, title, message, created_at)
                    VALUES (:admin_id, :janitor_id, :bin_id, :type, :title, :message, NOW())
                ");
                $stmtN->execute([
                    ':admin_id' => null,
                    ':janitor_id' => $janitorId,
                    ':bin_id' => $bin_id,
                    ':type' => $notificationType,
                    ':title' => $title,
                    ':message' => $message
                ]);
            } else {
                if ($conn->query("SHOW TABLES LIKE 'notifications'")->num_rows > 0) {
                    $stmtN = $conn->prepare("
                        INSERT INTO notifications (admin_id, janitor_id, bin_id, notification_type, title, message, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, NOW())
                    ");
                    if ($stmtN) {
                        $adminParam = null;
                        $janitorParam = $janitorId;
                        $binParam = (int)$bin_id;
                        $typeParam = $notificationType;
                        $titleParam = $title;
                        $messageParam = $message;
                        $stmtN->bind_param("iiisss", $adminParam, $janitorParam, $binParam, $typeParam, $titleParam, $messageParam);
                        $stmtN->execute();
                        $stmtN->close();
                    }
                }
            }
        } catch (Exception $e) {
            error_log("[janitor_assigned_bins] notification insert failed: " . $e->getMessage());
        }

        echo json_encode(['success' => true, 'status' => $status, 'affected' => $affected]);
        exit;
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        exit;
    }
}

// Delete bin
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'janitor_delete_bin') {
  header('Content-Type: application/json; charset=utf-8');
  try {
    if (!$janitorId) throw new Exception('Unauthorized');
    $bin_id = intval($_POST['bin_id'] ?? 0);
    if ($bin_id <= 0) throw new Exception('Invalid bin id');

    // Ensure the bin exists and is assigned to this janitor
    $assigned_to = null;
    if (isset($pdo) && $pdo instanceof PDO) {
      $stmt = $pdo->prepare("SELECT assigned_to FROM bins WHERE bin_id = ? LIMIT 1");
      $stmt->execute([$bin_id]);
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if (!$row) throw new Exception('Bin not found');
      $assigned_to = intval($row['assigned_to'] ?? 0);
    } else {
      $stmt = $conn->prepare("SELECT assigned_to FROM bins WHERE bin_id = ? LIMIT 1");
      if (!$stmt) throw new Exception('DB prepare failed: ' . $conn->error);
      $stmt->bind_param('i', $bin_id);
      $stmt->execute();
      $res = $stmt->get_result();
      $row = $res ? $res->fetch_assoc() : null;
      if (!$row) throw new Exception('Bin not found');
      $assigned_to = intval($row['assigned_to'] ?? 0);
    }

    if ($assigned_to !== $janitorId) {
      throw new Exception('Permission denied');
    }

    // Delete in transaction
    if (isset($pdo) && $pdo instanceof PDO) {
      $pdo->beginTransaction();
      try { $stmt = $pdo->prepare("DELETE FROM notifications WHERE bin_id = ?"); $stmt->execute([$bin_id]); } catch (Exception $e) { }
      try { $pdo->exec("DELETE FROM bin_history WHERE bin_id = " . intval($bin_id)); } catch (Exception $e) { }
      $stmt = $pdo->prepare("DELETE FROM bins WHERE bin_id = ?");
      $stmt->execute([$bin_id]);
      $deleted = $stmt->rowCount();
      $pdo->commit();
    } else {
      $conn->begin_transaction();
      if ($conn->query("SHOW TABLES LIKE 'notifications'")->num_rows > 0) {
        $dstmt = $conn->prepare("DELETE FROM notifications WHERE bin_id = ?");
        if ($dstmt) { $dstmt->bind_param('i', $bin_id); $dstmt->execute(); $dstmt->close(); }
      }
      $exists = $conn->query("SHOW TABLES LIKE 'bin_history'");
      if ($exists && $exists->num_rows > 0) {
        $conn->query("DELETE FROM bin_history WHERE bin_id = " . intval($bin_id));
      }
      $del = $conn->prepare("DELETE FROM bins WHERE bin_id = ?");
      if (!$del) { $conn->rollback(); throw new Exception('DB prepare failed: ' . $conn->error); }
      $del->bind_param('i', $bin_id);
      $del->execute();
      $deleted = $del->affected_rows;
      $del->close();
      $conn->commit();
    }

    echo json_encode(['success' => true, 'deleted' => $deleted, 'bin_id' => $bin_id]);
    exit;
  } catch (Exception $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) { try { $pdo->rollBack(); } catch(Exception $ee){} }
    if (!isset($pdo) && isset($conn) && $conn->errno) { try { $conn->rollback(); } catch(Exception $ee){} }
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    exit;
  }
}

// Get dashboard stats for assigned bins
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'get_dashboard_stats') {
    $dashboard_bins = [];
    $assignedBins = 0;
    $fullBins = 0;
    $pendingTasks = 0;
    $completedToday = 0;

    try {
        if ($janitorId > 0) {
            // bins assigned to this janitor
            $bins_query = "SELECT bins.*, CONCAT(j.first_name, ' ', j.last_name) AS janitor_name
                           FROM bins
                           LEFT JOIN janitors j ON bins.assigned_to = j.janitor_id
                           WHERE bins.assigned_to = " . $conn->real_escape_string($janitorId) . "
                           ORDER BY
                             CASE WHEN (bins.status = 'full' OR (bins.capacity IS NOT NULL && bins.capacity >= 100)) THEN 0 ELSE 1 END,
                             bins.capacity DESC,
                             bins.created_at DESC
                           LIMIT 500";
            $bins_res = $conn->query($bins_query);
            if ($bins_res) {
                while ($r = $bins_res->fetch_assoc()) $dashboard_bins[] = $r;
            }

            // assigned bins count
            $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId));
            if ($r && $row = $r->fetch_assoc()) $assignedBins = intval($row['c'] ?? 0);

            // full bins
            $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId) . " AND (status = 'full' OR (capacity IS NOT NULL AND capacity >= 100))");
            if ($r && $row = $r->fetch_assoc()) $fullBins = intval($row['c'] ?? 0);

            $pendingTasks = $fullBins;
            $completedToday = 0;
        }
    } catch (Exception $e) {
        // ignore
    }

    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'bins' => $dashboard_bins,
        'assignedBins' => $assignedBins,
        'fullBins' => $fullBins,
        'pendingTasks' => $pendingTasks,
        'completedToday' => $completedToday,
        'janitorId' => $janitorId
    ]);
    exit;
}

// Fetch initial data for page rendering
$assignedBins = 0;
$fullBins = 0;
$pendingTasks = 0;
$completedToday = 0;
$dashboard_bins = [];

try {
    if ($janitorId > 0) {
        $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId));
        if ($r && $row = $r->fetch_assoc()) $assignedBins = intval($row['c'] ?? 0);

        $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId) . " AND (bins.status = 'full' OR (bins.capacity IS NOT NULL AND bins.capacity >= 100))");
        if ($r && $row = $r->fetch_assoc()) $fullBins = intval($row['c'] ?? 0);

        $pendingTasks = $fullBins;

        // fetch bins
        $bins_query = "SELECT bins.*, CONCAT(j.first_name, ' ', j.last_name) AS janitor_name
                       FROM bins
                       LEFT JOIN janitors j ON bins.assigned_to = j.janitor_id
                       WHERE bins.assigned_to = " . $conn->real_escape_string($janitorId) . "
                       ORDER BY
                         CASE WHEN (bins.status = 'full' OR (bins.capacity IS NOT NULL && bins.capacity >= 100)) THEN 0 ELSE 1 END,
                         bins.capacity DESC,
                         bins.created_at DESC
                       LIMIT 200";
        $bins_res = $conn->query($bins_query);
        if ($bins_res) {
            while ($r = $bins_res->fetch_assoc()) $dashboard_bins[] = $r;
        }

        $completedToday = 0;
    }
} catch (Exception $e) {
    // ignore
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Assigned Bins - Trashbin Management</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <link rel="stylesheet" href="css/bootstrap.min.css">
  <link rel="stylesheet" href="css/janitor-dashboard.css">
  <style>
    .bin-detail-header { display:flex; align-items:center; justify-content:space-between; gap:1rem; }
    .bin-status-badge { font-size:0.9rem; padding: .45rem .65rem; }
    .bin-detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
    @media (max-width:576px){ .bin-detail-grid{grid-template-columns:1fr;} }
    .map-placeholder { background:#f7f7f7; height:140px; display:flex; align-items:center; justify-content:center; color:#888; border-radius:6px; }
    .table-responsive { overflow: visible !important; }
    .action-buttons { position: relative; display:flex; gap:.5rem; align-items:center; justify-content:flex-end; }
    .action-buttons .dropdown-menu { min-width: 220px; max-width: 350px; z-index: 2000; }
  </style>
</head>
<body>
  <div id="scrollProgress" class="scroll-progress"></div>
  <?php include_once __DIR__ . '/includes/header-admin.php'; ?>

  <div class="dashboard">
    <div class="background-circle background-circle-1"></div>
    <div class="background-circle background-circle-2"></div>
    <div class="background-circle background-circle-3"></div>

    <!-- Sidebar -->
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <h6 class="sidebar-title">Menu</h6>
      </div>
      <a href="janitor-dashboard.php" class="sidebar-item">
        <i class="fa-solid fa-chart-pie"></i><span>Dashboard</span>
      </a>
      <a href="janitor-assigned-bins.php" class="sidebar-item active">
        <i class="fa-solid fa-trash-alt"></i><span>Assigned Bins</span>
      </a>
      <a href="janitor-alerts.php" class="sidebar-item">
        <i class="fa-solid fa-bell"></i><span>Alerts</span>
      </a>
      <a href="janitor-profile.php" class="sidebar-item">
        <i class="fa-solid fa-user"></i><span>My Profile</span>
      </a>
    </aside>

    <!-- Main content -->
    <main class="content">
      <div class="section-header d-flex justify-content-between align-items-center">
        <div>
          <h1 class="page-title">Assigned Bins</h1>
          <p class="page-subtitle">Manage and monitor your assigned waste bins.</p>
        </div>
          <div class="d-flex gap-2">
          <div class="input-group" style="max-width: 300px;">
            <span class="input-group-text bg-white border-end-0"><i class="fas fa-search text-muted"></i></span>
            <input type="text" class="form-control border-start-0 ps-0" id="searchBinsInput" placeholder="Search bins...">
          </div>
          <div class="dropdown">
            <button class="btn btn-sm filter-btn dropdown-toggle" type="button" id="filterBinsDropdown" data-bs-toggle="dropdown" aria-expanded="false">
              <i class="fas fa-filter me-1"></i>Filter
            </button>
            <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="filterBinsDropdown">
              <li><a class="dropdown-item" href="#" data-filter="all">All Bins</a></li>
              <li><hr class="dropdown-divider"></li>
              <li><a class="dropdown-item" href="#" data-filter="needs_attention">Needs Attention</a></li>
              <li><a class="dropdown-item" href="#" data-filter="full">Full</a></li>
              <li><a class="dropdown-item" href="#" data-filter="half_full">Half Full</a></li>
              <li><a class="dropdown-item" href="#" data-filter="empty">Empty</a></li>
            </ul>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table mb-0">
              <thead>
                <tr>
                  <th>Bin ID</th><th>Location</th><th>Type</th><th>Status</th><th>Last Emptied</th><th class="text-end">Action</th>
                </tr>
              </thead>
              <tbody id="assignedBinsBody">
                <?php if (!empty($dashboard_bins)): foreach ($dashboard_bins as $b): ?>
                  <tr data-bin-id="<?php echo intval($b['bin_id']); ?>" data-status="<?php echo htmlspecialchars($b['status'] ?? ''); ?>">
                    <td><strong><?php echo htmlspecialchars($b['bin_code'] ?? $b['bin_id']); ?></strong></td>
                    <td><?php echo htmlspecialchars($b['location'] ?? ''); ?></td>
                    <td><?php echo htmlspecialchars($b['type'] ?? ''); ?></td>
                    <td>
                      <?php
                        $s = $b['status'] ?? '';
                        $display = match($s) {
                          'full' => 'Full',
                          'empty' => 'Empty',
                          'half_full' => 'Half Full',
                          'needs_attention' => 'Needs Attention',
                          'out_of_service' => 'Out of Service',
                          default => $s
                        };
                        $badge = ($s === 'full') ? 'danger' : (($s === 'empty') ? 'success' : (($s === 'half_full') ? 'warning' : 'secondary'));
                      ?>
                      <span class="badge bg-<?php echo $badge; ?>"><?php echo htmlspecialchars($display); ?></span>
                    </td>
                    <td><?php echo htmlspecialchars($b['last_emptied'] ?? $b['updated_at'] ?? 'N/A'); ?></td>
                    <td class="text-end">
                      <button class="btn btn-sm btn-primary me-2" onclick="openUpdateBinStatusModal(<?php echo intval($b['bin_id']); ?>)">Update</button>
                      <button class="btn btn-sm btn-outline-danger" onclick="openDeleteBinConfirm(<?php echo intval($b['bin_id']); ?>, this)">Delete</button>
                    </td>
                  </tr>
                <?php endforeach; endif; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </main>
  </div>

  <!-- Update Bin Status Modal -->
  <div class="modal fade" id="updateBinStatusModal" tabindex="-1">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="fas fa-sync-alt me-2"></i>Update Bin Status</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <form id="updateBinStatusForm">
            <input type="hidden" id="updateBinId">
            <div class="mb-3">
              <label class="form-label fw-bold">Bin ID</label>
              <p id="updateBinIdDisplay" class="mb-0"></p>
            </div>
            <div class="mb-3">
              <label class="form-label fw-bold">Location</label>
              <p id="updateBinLocation" class="mb-0"></p>
            </div>
            <div class="mb-3">
              <label class="form-label">New Status</label>
              <select class="form-control form-select" id="updateNewStatus" required>
                <option value="">Select status...</option>
                <option value="empty">Empty</option>
                <option value="half_full">Half Full</option>
                <option value="needs_attention">Needs Attention</option>
                <option value="full">Full</option>
              </select>
            </div>
            <div class="mb-3">
              <label class="form-label">Action Type (optional)</label>
              <select class="form-control form-select" id="updateActionType">
                <option value="">Select action...</option>
                <option value="emptied">Emptying Bin</option>
                <option value="cleaning">Cleaning Bin</option>
                <option value="inspection">Inspection</option>
                <option value="maintenance">Maintenance</option>
              </select>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
          <button type="button" class="btn btn-primary" id="updateStatusBtn"><i class="fas fa-save me-1"></i>Update Status</button>
        </div>
      </div>
    </div>
  </div>

  <!-- View Details Modal -->
  <div class="modal fade" id="viewDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title"><i class="fas fa-trash-can me-2"></i>Bin Details</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">Loading...</div>
        <div class="modal-footer">
          <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <?php include_once __DIR__ . '/includes/footer-admin.php'; ?>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
  (function(){
    let currentFilter = 'all';
    let currentSearch = '';

    function escapeHtml(s) {
      if (s === null || s === undefined) return '';
      return String(s)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    const JANITOR_ID = <?php echo intval($janitorId); ?>;

    // Load dashboard data
    async function loadDashboardData(filter = 'all') {
      try {
        currentFilter = filter || currentFilter || 'all';
        const url = new URL(window.location.href);
        url.searchParams.set('action', 'get_dashboard_stats');
        url.searchParams.set('filter', currentFilter);
        const resp = await fetch(url.toString(), { credentials: 'same-origin' });
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data || !data.success) return;

        const tbody = document.getElementById('assignedBinsBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        const bins = data.bins || [];
        if (!bins.length) {
          tbody.innerHTML = '';
        } else {
          bins.forEach(b => {
            let statusKey = (b.status || '').toString();
            if (statusKey === 'in_progress') statusKey = 'half_full';
            const statusMap = {
              'full': ['danger', 'Full'],
              'empty': ['success', 'Empty'],
              'half_full': ['warning', 'Half Full'],
              'needs_attention': ['info', 'Needs Attention'],
              'out_of_service': ['secondary', 'Out of Service'],
              'disabled': ['secondary', 'Disabled']
            };
            const meta = statusMap[statusKey] || ['secondary', statusKey || 'N/A'];
            const lastEmptied = b.last_emptied || b.updated_at || 'N/A';
            const binCode = b.bin_code || b.bin_id;
            const type = b.type || '';
            const escapedBinId = parseInt(b.bin_id,10);
            tbody.insertAdjacentHTML('beforeend', `
              <tr data-bin-id="${escapedBinId}" data-status="${encodeURIComponent(statusKey)}">
                <td><strong>${escapeHtml(binCode)}</strong></td>
                <td>${escapeHtml(b.location || '')}</td>
                <td>${escapeHtml(type)}</td>
                <td><span class="badge bg-${meta[0]}">${escapeHtml(meta[1])}</span></td>
                <td>${escapeHtml(lastEmptied)}</td>
                <td class="text-end">
                  <button class="btn btn-sm btn-primary me-2" onclick="openUpdateBinStatusModal(${escapedBinId})">Update</button>
                  <button class="btn btn-sm btn-outline-danger" onclick="openDeleteBinConfirm(${escapedBinId}, this)">Delete</button>
                </td>
              </tr>
            `);
          });
        }

        applySearchFilter();
      } catch (err) {
        console.warn('Dashboard refresh error', err);
      }
    }

    window.openUpdateBinStatusModal = function(binId) {
      fetch('bins.php?action=get_details&bin_id=' + encodeURIComponent(binId), { credentials: 'same-origin' })
        .then(r => r.json())
        .then(data => {
          if (!data || !data.success || !data.bin) {
            document.getElementById('updateBinId').value = binId;
            document.getElementById('updateBinIdDisplay').textContent = binId;
            document.getElementById('updateBinLocation').textContent = 'N/A';
            document.getElementById('updateNewStatus').value = '';
          } else {
            const bin = data.bin;
            let curStatus = bin.status || '';
            if (curStatus === 'in_progress') curStatus = 'half_full';
            document.getElementById('updateBinId').value = bin.bin_id || binId;
            document.getElementById('updateBinIdDisplay').textContent = bin.bin_code || ('Bin ' + bin.bin_id);
            document.getElementById('updateBinLocation').textContent = bin.location || ' N/A';
            document.getElementById('updateNewStatus').value = curStatus;
          }
          document.getElementById('updateActionType').value = '';
          new bootstrap.Modal(document.getElementById('updateBinStatusModal')).show();
        })
        .catch(err => {
          console.warn('Failed to fetch bin details', err);
          document.getElementById('updateBinId').value = binId;
          document.getElementById('updateBinIdDisplay').textContent = binId;
          new bootstrap.Modal(document.getElementById('updateBinStatusModal')).show();
        });
    };

    async function submitBinStatusUpdate() {
      const binId = document.getElementById('updateBinId').value;
      let newStatus = document.getElementById('updateNewStatus').value;
      const actionType = document.getElementById('updateActionType').value || '';

      if (!newStatus) { alert('Please select a new status'); return; }
      if (newStatus === 'in_progress') newStatus = 'half_full';

      try {
        const formData = new URLSearchParams();
        formData.append('action', 'janitor_edit_status');
        formData.append('bin_id', binId);
        formData.append('status', newStatus);
        if (actionType) formData.append('action_type', actionType);

        const resp = await fetch(window.location.pathname, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type':'application/x-www-form-urlencoded'},
          body: formData.toString()
        });
        const json = await resp.json();
        if (json && json.success) {
          const modalEl = document.getElementById('updateBinStatusModal');
          const modal = bootstrap.Modal.getInstance(modalEl);
          if (modal) modal.hide();
          await loadDashboardData();
          alert('Status updated successfully');
        } else {
          alert((json && json.message) ? json.message : 'Failed to update status');
        }
      } catch (e) {
        console.error('Update failed', e);
        alert('Server error while updating status');
      }
    }

    window.openDeleteBinConfirm = function(binId, btnEl) {
      try {
        const ok = confirm('Delete this bin and all its related data? This action is permanent. Are you sure?');
        if (!ok) return;
        performDeleteBin(binId, btnEl);
      } catch (e) { console.warn('delete confirm error', e); }
    }

    async function performDeleteBin(binId, btnEl) {
      try {
        if (btnEl) btnEl.disabled = true;
        const payload = new URLSearchParams();
        payload.append('action','janitor_delete_bin');
        payload.append('bin_id', String(binId));

        const resp = await fetch(window.location.pathname, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type':'application/x-www-form-urlencoded'},
          body: payload.toString()
        });
        const json = await resp.json();
        if (!json || !json.success) {
          alert((json && json.message) ? json.message : 'Failed to delete bin');
          if (btnEl) btnEl.disabled = false;
          return;
        }

        const row = document.querySelector('tr[data-bin-id="' + parseInt(binId,10) + '"]');
        if (row) row.remove();

        await loadDashboardData();
        alert('Bin deleted successfully');
      } catch (err) {
        console.error('performDeleteBin error', err);
        alert('Server error while deleting bin');
        if (btnEl) btnEl.disabled = false;
      }
    }

    window.openViewDetails = function(e, binId) {
      if (e && e.preventDefault) e.preventDefault();
      fetch('bins.php?action=get_details&bin_id=' + encodeURIComponent(binId), { credentials: 'same-origin' })
        .then(r => r.json())
        .then(data => {
          if (!data || !data.success || !data.bin) {
            alert('Failed to load bin details');
            return;
          }
          const bin = data.bin;
          const body = document.querySelector('#viewDetailsModal .modal-body');
          if (body) {
            body.innerHTML = `
              <div class="row mb-3">
                <div class="col-md-6"><p><strong>Bin Code:</strong><br>${escapeHtml(bin.bin_code || 'N/A')}</p></div>
                <div class="col-md-6"><p><strong>Type:</strong><br>${escapeHtml(bin.type || 'N/A')}</p></div>
              </div>
              <div class="row mb-3">
                <div class="col-md-6"><p><strong>Location:</strong><br>${escapeHtml(bin.location || 'N/A')}</p></div>
                <div class="col-md-6"><p><strong>Assigned To:</strong><br>${escapeHtml(bin.janitor_name || 'Unassigned')}</p></div>
              </div>
              <div class="row mb-3">
                <div class="col-md-6"><p><strong>Status:</strong><br><span class="badge bg-info">${escapeHtml(bin.status || 'N/A')}</span></p></div>
                <div class="col-md-6"><p><strong>Capacity:</strong><br>${escapeHtml((bin.capacity !== undefined && bin.capacity !== null) ? bin.capacity + '%' : 'N/A')}</p></div>
              </div>
              <hr>
              <div class="alert alert-info small"><i class="fas fa-info-circle me-2"></i>Status and capacity are managed by the microcontroller in real-time.</div>
            `;
          }
          const modalEl = document.getElementById('viewDetailsModal');
          if (modalEl) new bootstrap.Modal(modalEl).show();
        })
        .catch(err => {
          console.error('Failed to fetch bin details', err);
          alert('Failed to load details');
        });
    };

    document.addEventListener('click', function(e) {
      if (e.target && e.target.closest && e.target.closest('#updateStatusBtn')) {
        e.preventDefault();
        submitBinStatusUpdate();
      }
    });

    function applySearchFilter() {
      const tbody = document.getElementById('assignedBinsBody');
      if (!tbody) return;
      const rows = tbody.querySelectorAll('tr[data-bin-id]');
      let visibleCount = 0;
      rows.forEach(row => {
        const statusEncoded = row.getAttribute('data-status') || '';
        const status = decodeURIComponent(statusEncoded);
        let visible = (currentFilter === 'all') || (status === currentFilter);
        if (visible && currentSearch) {
          const text = row.textContent.toLowerCase();
          visible = text.includes(currentSearch.toLowerCase());
        }
        row.style.display = visible ? '' : 'none';
        if (visible) visibleCount++;
      });
      let noResultsRow = tbody.querySelector('tr.no-results-message');
      if (visibleCount === 0) {
        if (!noResultsRow) {
          noResultsRow = document.createElement('tr');
          noResultsRow.className = 'no-results-message';
          noResultsRow.innerHTML = '<td colspan="6" class="text-center py-4 text-muted">No bins found</td>';
          tbody.appendChild(noResultsRow);
        }
        noResultsRow.style.display = '';
      } else {
        if (noResultsRow) noResultsRow.style.display = 'none';
      }
    }

    document.addEventListener('DOMContentLoaded', function() {
      const searchInput = document.getElementById('searchBinsInput');
      if (searchInput) {
        searchInput.addEventListener('input', function() {
          currentSearch = this.value.trim();
          applySearchFilter();
        });
      }

      document.querySelectorAll('#filterBinsDropdown').closest('.dropdown').querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', function(e) {
          e.preventDefault();
          let filter = this.getAttribute('data-filter') || 'all';
          if (filter === 'in_progress') filter = 'half_full';
          currentFilter = filter;
          loadDashboardData(filter);
        });
      });

      loadDashboardData();
      setInterval(()=>loadDashboardData(currentFilter), 1000);
    });

  })();
  </script>
  <script src="js/scroll-progress.js"></script>
  <script src="js/password-toggle.js"></script>
</body>
</html>
