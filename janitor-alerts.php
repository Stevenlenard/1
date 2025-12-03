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

// determine janitor display name for admin notifications
$janitorDisplayName = $_SESSION['name'] ?? ($_SESSION['first_name'] ?? 'Janitor');

// helper: check if a column exists (works with PDO or mysqli)
function column_exists_in_table($table, $column) {
    global $pdo, $conn;
    try {
        if (isset($pdo) && $pdo instanceof PDO) {
            $r = $pdo->query("SHOW COLUMNS FROM `{$table}` LIKE " . $pdo->quote($column));
            return ($r && $r->rowCount() > 0);
        } else {
            $r = $conn->query("SHOW COLUMNS FROM `{$table}` LIKE '" . $conn->real_escape_string($column) . "'");
            return ($r && $r->num_rows > 0);
        }
    } catch (Exception $e) {
        return false;
    }
}

// AJAX GET endpoints for alerts
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action'])) {
    header('Content-Type: application/json; charset=utf-8');

    // Alerts / notifications relevant to this janitor
    if ($_GET['action'] === 'get_alerts') {
        $alerts = [];
        try {
            // decide whether notifications table has is_deleted column
            $hasIsDeleted = column_exists_in_table('notifications', 'is_deleted');

            if (isset($pdo) && $pdo instanceof PDO) {
                $whereDeleted = $hasIsDeleted ? "(n.is_deleted IS NULL OR n.is_deleted = 0)" : "1=1";
                $sql = "
                    SELECT n.notification_id, n.created_at, n.title, n.message, n.bin_id, b.bin_code, n.is_read
                    FROM notifications n
                    LEFT JOIN bins b ON n.bin_id = b.bin_id
                    WHERE {$whereDeleted}
                      AND (n.janitor_id = :jid OR (n.janitor_id IS NULL AND n.bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = :jid2)))
                    ORDER BY n.created_at DESC
                    LIMIT 200
                ";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([':jid' => $janitorId, ':jid2' => $janitorId]);
                $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $whereDeleted = $hasIsDeleted ? "(n.is_deleted IS NULL OR n.is_deleted = 0)" : "1=1";
                $sql = "
                    SELECT n.notification_id, n.created_at, n.title, n.message, n.bin_id, b.bin_code, n.is_read
                    FROM notifications n
                    LEFT JOIN bins b ON n.bin_id = b.bin_id
                    WHERE {$whereDeleted}
                      AND (n.janitor_id = ? OR (n.janitor_id IS NULL AND n.bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = ?)))
                    ORDER BY n.created_at DESC
                    LIMIT 200
                ";
                $stmt = $conn->prepare($sql);
                if (!$stmt) {
                    // surface SQL error for easier debugging
                    throw new Exception('DB prepare failed: ' . $conn->error);
                }
                $stmt->bind_param("ii", $janitorId, $janitorId);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) $alerts[] = $row;
                $stmt->close();
            }
        } catch (Exception $e) {
            // return error details so you can see why no rows (remove/keep in production)
            http_response_code(500);
            echo json_encode(['success' => false, 'alerts' => [], 'error' => $e->getMessage()]);
            exit;
        }

        echo json_encode(['success' => true, 'alerts' => $alerts]);
        exit;
    }
}
// end GET endpoints

// NEW: POST endpoints for marking, deleting, and clearing alerts (connected to notifications table)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $action = $_POST['action'];

    try {
        // Mark single notification as read (acknowledge) and create admin-visible notification
        if ($action === 'mark_read' && isset($_POST['id'])) {
            $id = intval($_POST['id']);
            if ($id <= 0) throw new Exception('Invalid id');

            // fetch original notification details first (to include context in admin notification)
            $origTitle = '';
            $origMessage = '';
            $origBinId = null;
            $origAdminId = null;
            if (isset($pdo) && $pdo instanceof PDO) {
                $sel = $pdo->prepare("SELECT title, message, bin_id, admin_id FROM notifications WHERE notification_id = ? LIMIT 1");
                $sel->execute([$id]);
                $row = $sel->fetch(PDO::FETCH_ASSOC);
                if ($row) {
                    $origTitle = $row['title'] ?? '';
                    $origMessage = $row['message'] ?? '';
                    $origBinId = $row['bin_id'] !== null ? intval($row['bin_id']) : null;
                    $origAdminId = $row['admin_id'] !== null ? intval($row['admin_id']) : null;
                }
            } else {
                $sel = $conn->prepare("SELECT title, message, bin_id, admin_id FROM notifications WHERE notification_id = ? LIMIT 1");
                if ($sel) {
                    $sel->bind_param("i", $id);
                    $sel->execute();
                    $res = $sel->get_result();
                    if ($r = $res->fetch_assoc()) {
                        $origTitle = $r['title'] ?? '';
                        $origMessage = $r['message'] ?? '';
                        $origBinId = $r['bin_id'] !== null ? intval($r['bin_id']) : null;
                        $origAdminId = $r['admin_id'] !== null ? intval($r['admin_id']) : null;
                    }
                    $sel->close();
                }
            }

            // mark the original notification as read for this janitor
            if (isset($pdo) && $pdo instanceof PDO) {
                $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1, read_at = NOW() WHERE notification_id = ? AND (janitor_id = ? OR janitor_id IS NULL)");
                $stmt->execute([$id, $janitorId]);
            } else {
                $stmt = $conn->prepare("UPDATE notifications SET is_read = 1, read_at = NOW() WHERE notification_id = ? AND (janitor_id = ? OR janitor_id IS NULL)");
                if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
                $stmt->bind_param("ii", $id, $janitorId);
                $stmt->execute();
                $stmt->close();
            }

            // Create an admin-facing notification so admins see the acknowledgement in admin notifications list.
            // Insert into notifications table: admin_id NULL, janitor_id = janitor who acknowledged, bin_id optional.
            $adminTitle = 'Acknowledged: ' . ($origTitle ?: 'Notification');
            $adminMessage = $janitorDisplayName . ' has acknowledged the notification' . ($origTitle ? ' about "' . $origTitle . '"' : '') . '.';
            $notificationType = 'info';

            if (isset($pdo) && $pdo instanceof PDO) {
                $ins = $pdo->prepare("
                    INSERT INTO notifications (admin_id, janitor_id, bin_id, notification_type, title, message, is_read, created_at)
                    VALUES (:admin_id, :janitor_id, :bin_id, :type, :title, :message, 0, NOW())
                ");
                // admin_id null so pass null
                $ins->execute([
                    ':admin_id' => null,
                    ':janitor_id' => $janitorId,
                    ':bin_id' => $origBinId,
                    ':type' => $notificationType,
                    ':title' => $adminTitle,
                    ':message' => $adminMessage
                ]);
            } else {
                // mysqli branch - escape values and insert; allow NULL for bin_id
                $titleEsc = $conn->real_escape_string($adminTitle);
                $msgEsc = $conn->real_escape_string($adminMessage);
                $binValue = $origBinId !== null ? intval($origBinId) : 'NULL';
                $sql = "INSERT INTO notifications (admin_id, janitor_id, bin_id, notification_type, title, message, is_read, created_at)
                        VALUES (NULL, " . intval($janitorId) . ", {$binValue}, 'info', '{$titleEsc}', '{$msgEsc}', 0, NOW())";
                $conn->query($sql);
            }

            echo json_encode(['success' => true, 'notification_id' => $id]);
            exit;
        }

        // Mark all as read for this janitor (and related bins)
        if ($action === 'mark_all_read') {
            $sql = "UPDATE notifications SET is_read = 1, read_at = NOW() WHERE (janitor_id = ? OR (janitor_id IS NULL AND bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = ?)))";
            if (isset($pdo) && $pdo instanceof PDO) {
                $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1, read_at = NOW() WHERE (janitor_id = :jid OR (janitor_id IS NULL AND bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = :jid2)))");
                $stmt->execute([':jid' => $janitorId, ':jid2' => $janitorId]);
            } else {
                $stmt = $conn->prepare($sql);
                if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
                $stmt->bind_param("ii", $janitorId, $janitorId);
                $stmt->execute();
                $stmt->close();
            }
            echo json_encode(['success' => true, 'message' => 'All notifications marked as read']);
            exit;
        }

        // Clear all (soft-delete) for this janitor
        if ($action === 'clear_all') {
            $sql = "UPDATE notifications SET is_deleted = 1 WHERE (is_deleted IS NULL OR is_deleted = 0) AND (janitor_id = ? OR (janitor_id IS NULL AND bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = ?)))";
            if (isset($pdo) && $pdo instanceof PDO) {
                if (!column_exists_in_table('notifications', 'is_deleted')) {
                    $stmt = $pdo->prepare("DELETE FROM notifications WHERE (janitor_id = :jid OR (janitor_id IS NULL AND bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = :jid2)))");
                    $stmt->execute([':jid' => $janitorId, ':jid2' => $janitorId]);
                } else {
                    $stmt = $pdo->prepare("UPDATE notifications SET is_deleted = 1 WHERE (is_deleted IS NULL OR is_deleted = 0) AND (janitor_id = :jid OR (janitor_id IS NULL AND bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = :jid2)))");
                    $stmt->execute([':jid' => $janitorId, ':jid2' => $janitorId]);
                }
            } else {
                if (column_exists_in_table('notifications', 'is_deleted')) {
                    $stmt = $conn->prepare($sql);
                    if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
                    $stmt->bind_param("ii", $janitorId, $janitorId);
                    $stmt->execute();
                    $stmt->close();
                } else {
                    $stmt = $conn->prepare("DELETE FROM notifications WHERE (janitor_id = ? OR (janitor_id IS NULL AND bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = ?)))");
                    if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
                    $stmt->bind_param("ii", $janitorId, $janitorId);
                    $stmt->execute();
                    $stmt->close();
                }
            }
            echo json_encode(['success' => true, 'message' => 'Notifications cleared']);
            exit;
        }

        // Delete single notification (soft-delete) for this janitor
        if ($action === 'delete_notification' && isset($_POST['id'])) {
            $id = intval($_POST['id']);
            if ($id <= 0) throw new Exception('Invalid id');

            if (isset($pdo) && $pdo instanceof PDO) {
                if (column_exists_in_table('notifications', 'is_deleted')) {
                    $stmt = $pdo->prepare("UPDATE notifications SET is_deleted = 1 WHERE notification_id = :id AND (janitor_id = :jid OR janitor_id IS NULL)");
                    $stmt->execute([':id' => $id, ':jid' => $janitorId]);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM notifications WHERE notification_id = :id AND (janitor_id = :jid OR janitor_id IS NULL)");
                    $stmt->execute([':id' => $id, ':jid' => $janitorId]);
                }
            } else {
                if (column_exists_in_table('notifications', 'is_deleted')) {
                    $stmt = $conn->prepare("UPDATE notifications SET is_deleted = 1 WHERE notification_id = ? AND (janitor_id = ? OR janitor_id IS NULL)");
                    if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
                    $stmt->bind_param("ii", $id, $janitorId);
                    $stmt->execute();
                    $stmt->close();
                } else {
                    $stmt = $conn->prepare("DELETE FROM notifications WHERE notification_id = ? AND (janitor_id = ? OR janitor_id IS NULL)");
                    if (!$stmt) throw new Exception('Prepare failed: ' . $conn->error);
                    $stmt->bind_param("ii", $id, $janitorId);
                    $stmt->execute();
                    $stmt->close();
                }
            }

            echo json_encode(['success' => true, 'notification_id' => $id]);
            exit;
        }
    } catch (Exception $e) {
        // return error
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        exit;
    }

    echo json_encode(['success' => false, 'message' => 'Invalid request']);
    exit;
}

// Fetch initial alerts for page
$recent_alerts = [];
try {
    if ($janitorId > 0) {
        $hasIsDeleted = column_exists_in_table('notifications', 'is_deleted');
        $whereDeleted = $hasIsDeleted ? "(n.is_deleted IS NULL OR n.is_deleted = 0)" : "1=1";

        if (isset($pdo) && $pdo instanceof PDO) {
            $sql = "
                SELECT n.notification_id, n.created_at, n.title, n.message, n.bin_id, b.bin_code, b.location, n.is_read
                FROM notifications n
                LEFT JOIN bins b ON n.bin_id = b.bin_id
                WHERE {$whereDeleted}
                  AND (n.janitor_id = :jid OR (n.janitor_id IS NULL AND n.bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = :jid2)))
                ORDER BY n.created_at DESC
                LIMIT 200
            ";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':jid' => $janitorId, ':jid2' => $janitorId]);
            $recent_alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } else {
            $sql = "
                SELECT n.notification_id, n.created_at, n.title, n.message, n.bin_id, b.bin_code, b.location, n.is_read
                FROM notifications n
                LEFT JOIN bins b ON n.bin_id = b.bin_id
                WHERE {$whereDeleted}
                  AND (n.janitor_id = ? OR (n.janitor_id IS NULL AND n.bin_id IN (SELECT bin_id FROM bins WHERE assigned_to = ?)))
                ORDER BY n.created_at DESC
                LIMIT 200
            ";
            $stmt = $conn->prepare($sql);
            if ($stmt) {
                $stmt->bind_param("ii", $janitorId, $janitorId);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) $recent_alerts[] = $row;
                $stmt->close();
            } else {
                // if prepare failed, log error (visible in server logs)
                error_log('janitor-alerts initial query prepare failed: ' . $conn->error);
            }
        }
    }
} catch (Exception $e) {
    // ignore but log for debugging
    error_log('janitor-alerts initial fetch error: ' . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Alerts - Trashbin Management</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <link rel="stylesheet" href="css/bootstrap.min.css">
  <link rel="stylesheet" href="css/janitor-dashboard.css">
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
      <a href="janitor-assigned-bins.php" class="sidebar-item">
        <i class="fa-solid fa-trash-alt"></i><span>Assigned Bins</span>
      </a>
      <a href="janitor-alerts.php" class="sidebar-item active">
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
          <h1 class="page-title">Alerts</h1>
          <p class="page-subtitle">Notifications about assigned bins and system messages.</p>
        </div>
        <div>
          <button class="btn btn-sm btn-outline-secondary" id="markAllReadBtn"><i class="fas fa-check-double"></i> Mark All Read</button>
          <button class="btn btn-sm btn-outline-danger ms-2" id="clearAlertsBtn"><i class="fas fa-trash-alt me-1"></i>Clear All</button>
          <div class="dropdown ms-2 d-inline-block">
            <button class="btn btn-sm filter-btn dropdown-toggle" type="button" id="filterAlertsDropdown" data-bs-toggle="dropdown" aria-expanded="false">
              <i class="fas fa-filter me-1"></i>Filter
            </button>
            <ul id="filterAlertsMenu" class="dropdown-menu dropdown-menu-end" aria-labelledby="filterAlertsDropdown">
              <li><a class="dropdown-item active" href="#" data-filter="all">All</a></li>
              <li><a class="dropdown-item" href="#" data-filter="unread">Unread</a></li>
              <li><a class="dropdown-item" href="#" data-filter="read">Read</a></li>
            </ul>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table mb-0">
              <thead>
                <tr><th>Time</th><th>Title</th><th class="d-none d-md-table-cell">Message</th><th class="d-none d-lg-table-cell">Target</th><th class="text-end">Action</th></tr>
              </thead>
              <tbody id="alertsBody">
                <?php if (empty($recent_alerts)): ?>
                  <tr><td colspan="5" class="text-center py-4 text-muted">Loading...</td></tr>
                <?php else: foreach ($recent_alerts as $a): 
                  $time = $a['created_at'] ?? 'N/A';
                  $title = htmlspecialchars($a['title'] ?? 'Notification', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                  $message = htmlspecialchars($a['message'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                  $target = !empty($a['bin_code']) ? htmlspecialchars($a['bin_code']) : (!empty($a['bin_id']) ? ('Bin #' . intval($a['bin_id'])) : '-');
                  $isRead = intval($a['is_read'] ?? 0) === 1;
                  $nid = intval($a['notification_id'] ?? 0);
                ?>
                <tr class="<?php echo $isRead ? 'table-light' : ''; ?>">
                  <td><?php echo htmlspecialchars($time); ?></td>
                  <td><?php echo $title; ?></td>
                  <td class="d-none d-md-table-cell"><small class="text-muted"><?php echo $message; ?></small></td>
                  <td class="d-none d-lg-table-cell"><?php echo $target; ?></td>
                  <td class="text-end">
                    <?php if ($isRead): ?>
                      <span class="text-muted small">Acknowledged</span>
                      <button class="btn btn-sm btn-outline-danger ms-2 del-btn" data-id="<?php echo $nid; ?>">Delete</button>
                    <?php else: ?>
                      <button class="btn btn-sm btn-success ack-btn me-2" data-id="<?php echo $nid; ?>">Acknowledge</button>
                      <button class="btn btn-sm btn-outline-danger del-btn" data-id="<?php echo $nid; ?>">Delete</button>
                    <?php endif; ?>
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

  <?php include_once __DIR__ . '/includes/footer-admin.php'; ?>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
  (function(){
    const JANITOR_ID = <?php echo intval($janitorId); ?>;
    const JANITOR_NAME = <?php echo json_encode($_SESSION['name'] ?? 'Janitor'); ?>;

    function escapeHtml(s) {
      if (s === null || s === undefined) return '';
      return String(s)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    // Alerts loader
    async function loadAlerts() {
      try {
        const resp = await fetch(window.location.pathname + '?action=get_alerts', { credentials: 'same-origin' });
        const json = await resp.json();
        const tbody = document.getElementById('alertsBody');
        tbody.innerHTML = '';
        if (!json.success || !json.alerts || !json.alerts.length) {
          const err = json.error ? ' — ' + escapeHtml(json.error) : '';
          tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">No alerts found' + err + '</td></tr>';
          return;
        }
        json.alerts.forEach(a => {
          const time = a.created_at || 'N/A';
          const title = a.title || 'Notification';
          const message = a.message || '';
          const target = a.bin_code || (a.bin_id ? ('Bin #' + a.bin_id) : '-');
          const isRead = parseInt(a.is_read || 0, 10) === 1;
          const nid = a.notification_id ? parseInt(a.notification_id, 10) : 0;

          const ackBtn = isRead ? '<span class="text-muted small">Acknowledged</span>' : `<button class="btn btn-sm btn-success ack-btn me-2" data-id="${nid}">Acknowledge</button>`;
          const delBtn = `<button class="btn btn-sm btn-outline-danger del-btn" data-id="${nid}">Delete</button>`;

          tbody.insertAdjacentHTML('beforeend', `
            <tr class="${isRead ? 'table-light' : ''}">
              <td>${escapeHtml(time)}</td>
              <td>${escapeHtml(title)}</td>
              <td class="d-none d-md-table-cell"><small class="text-muted">${escapeHtml(message)}</small></td>
              <td class="d-none d-lg-table-cell">${escapeHtml(target)}</td>
              <td class="text-end">${ackBtn}${delBtn}</td>
            </tr>
          `);
        });
      } catch (e) {
        console.warn('Failed to load alerts', e);
        document.getElementById('alertsBody').innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">Failed to load alerts</td></tr>';
      }
    }

    // Acknowledge / Delete handlers use delegation
    document.addEventListener('click', function(e) {
      const ack = e.target.closest && e.target.closest('.ack-btn');
      const del = e.target.closest && e.target.closest('.del-btn');

      if (ack) {
        e.preventDefault();
        const id = parseInt(ack.getAttribute('data-id') || 0, 10);
        if (!id) return;
        ack.disabled = true;
        ack.textContent = 'Acknowledging...';
        const payload = new URLSearchParams();
        payload.append('action', 'mark_read');
        payload.append('id', id);

        fetch(window.location.pathname, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type':'application/x-www-form-urlencoded'},
          body: payload.toString()
        }).then(r => r.json()).then(data => {
          if (data && data.success) {
            const row = ack.closest('tr');
            if (row) {
              row.classList.add('table-light');
              const ackBtnEl = row.querySelector('.ack-btn');
              if (ackBtnEl) ackBtnEl.remove();
              const lastCell = row.querySelector('td.text-end');
              if (lastCell && !lastCell.querySelector('.ack-label')) {
                const span = document.createElement('span'); span.className = 'ack-label text-muted small me-2'; span.textContent = 'Acknowledged';
                lastCell.prepend(span);
              }
            }
          } else {
            ack.disabled = false;
            ack.textContent = 'Acknowledge';
            alert((data && data.message) ? data.message : 'Failed to acknowledge alert');
          }
        }).catch(err => {
          console.warn('Acknowledge error', err);
          ack.disabled = false;
          ack.textContent = 'Acknowledge';
          alert('Server error while acknowledging alert');
        });
        return;
      }

      if (del) {
        e.preventDefault();
        const id = parseInt(del.getAttribute('data-id') || 0, 10);
        if (!id) return;
        if (!confirm('Delete this notification? This action can be undone only in the database.')) return;

        del.disabled = true;
        del.textContent = 'Deleting...';
        const payload = new URLSearchParams();
        payload.append('action', 'delete_notification');
        payload.append('id', id);

        fetch(window.location.pathname, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type':'application/x-www-form-urlencoded'},
          body: payload.toString()
        }).then(r => r.json()).then(data => {
          if (data && data.success) {
            const row = del.closest('tr');
            if (row) row.remove();
          } else {
            del.disabled = false;
            del.textContent = 'Delete';
            alert((data && data.message) ? data.message : 'Failed to delete notification');
          }
        }).catch(err => {
          console.warn('Delete error', err);
          del.disabled = false;
          del.textContent = 'Delete';
          alert('Server error while deleting notification');
        });
        return;
      }
    });

    document.addEventListener('DOMContentLoaded', function() {
      loadAlerts();

      // Mark all read -> use this endpoint (connected to notifications table)
      document.getElementById('markAllReadBtn').addEventListener('click', function(e) {
        e.preventDefault();
        if (!confirm('Mark all visible notifications as read?')) return;
        fetch(window.location.pathname, {
          method:'POST',
          credentials:'same-origin',
          headers:{'Content-Type':'application/x-www-form-urlencoded'},
          body: 'action=mark_all_read'
        }).then(r => r.json()).then(() => loadAlerts()).catch(()=>loadAlerts());
      });

      // Clear all -> soft-delete all relevant notifications
      document.getElementById('clearAlertsBtn').addEventListener('click', function(e) {
        e.preventDefault();
        if (!confirm('Clear all notifications? This will hide them from the UI (soft-delete).')) return;
        fetch(window.location.pathname, {
          method:'POST',
          credentials:'same-origin',
          headers:{'Content-Type':'application/x-www-form-urlencoded'},
          body: 'action=clear_all'
        }).then(res => res.json()).then(json => {
          loadAlerts();
        }).catch(()=>loadAlerts());
      });

      // Alerts filter dropdown
      document.querySelectorAll('#filterAlertsMenu .dropdown-item').forEach(item => {
        item.addEventListener('click', function(e) {
          e.preventDefault();
          const filter = this.getAttribute('data-filter') || 'all';
          document.querySelectorAll('#filterAlertsMenu .dropdown-item').forEach(it => it.classList.remove('active'));
          this.classList.add('active');

          const tbody = document.getElementById('alertsBody');
          if (!tbody) return;
          tbody.querySelectorAll('tr').forEach(r => r.style.display = '');

          if (filter === 'read') {
            tbody.querySelectorAll('tr').forEach(r => { if (!r.classList.contains('table-light')) r.style.display = 'none'; });
          } else if (filter === 'unread') {
            tbody.querySelectorAll('tr').forEach(r => { if (r.classList.contains('table-light')) r.style.display = 'none'; });
          }

          const existing = tbody.querySelector('tr.no-results');
          if (existing) existing.remove();

          const visible = Array.from(tbody.querySelectorAll('tr')).filter(r => r.style.display !== 'none').length;
          if (visible === 0) {
            tbody.insertAdjacentHTML('beforeend', '<tr class="no-results"><td colspan="5" class="text-center py-4 text-muted">No notifications found</td></tr>');
          }
        });
      });

      // Auto-refresh alerts every 5 seconds
      setInterval(loadAlerts, 5000);
    });

  })();
  </script>
  <script src="js/scroll-progress.js"></script>
</body>
</html>