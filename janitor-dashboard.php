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

  // Get dashboard stats endpoint
  if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'get_dashboard_stats') {
      $dashboard_bins = [];
      $assignedBins = 0;
      $fullBins = 0;
      $pendingTasks = 0;
      $completedToday = 0;

      try {
          if ($janitorId > 0) {
              // bins assigned to this janitor (full bins first)
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

              // full bins assigned to this janitor
              $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId) . " AND (status = 'full' OR (capacity IS NOT NULL AND capacity >= 100))");
              if ($r && $row = $r->fetch_assoc()) $fullBins = intval($row['c'] ?? 0);

              // pending tasks: interpret as number of full bins
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

  // Fetch initial stats & bins for PHP-rendered page
  $assignedBins = 0;
  $fullBins = 0;
  $pendingTasks = 0;
  $completedToday = 0;
  $dashboard_bins = [];
  $recent_alerts = [];

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

          $recent_alerts = $dashboard_bins;
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
    <title>Janitor Dashboard - Trashbin Management</title>
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
        <a href="janitor-dashboard.php" class="sidebar-item active">
          <i class="fa-solid fa-chart-pie"></i><span>Dashboard</span>
        </a>
        <a href="janitor-assigned-bins.php" class="sidebar-item">
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
            <h1 class="page-title">Dashboard</h1>
            <p class="page-subtitle">Welcome back! Here's your daily overview.</p>
          </div>
        </div>

        <!-- Stats -->
        <div class="row g-4 mb-4">
          <div class="col-md-4">
            <div class="stat-card">
              <div class="stat-icon"><i class="fa-solid fa-trash-alt"></i></div>
              <div class="stat-content">
                <h6>Assigned Bins</h6>
                <h2 id="assignedBinsCount"><?php echo intval($assignedBins); ?></h2>
                <small>Active assignments</small>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="stat-card">
              <div class="stat-icon warning"><i class="fa-solid fa-clock"></i></div>
              <div class="stat-content">
                <h6>Pending Tasks</h6>
                <h2 id="pendingTasksCount"><?php echo intval($pendingTasks); ?></h2>
                <small>Awaiting action</small>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="stat-card">
              <div class="stat-icon success"><i class="fa-solid fa-check-circle"></i></div>
              <div class="stat-content">
                <h6>Completed Today</h6>
                <h2 id="completedTodayCount"><?php echo intval($completedToday); ?></h2>
                <small>Great work!</small>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Alerts -->
        <div class="card mb-4 recent-alerts-card">
          <div class="card-header d-flex justify-content-between align-items-center">
              <h5 class="mb-0"><i class="fas fa-bell me-2"></i>Recent Alerts</h5>
              <a href="janitor-alerts.php" class="btn btn-sm view-all-link"><span>View All</span></a>
          </div>
          <div class="card-body p-4">
            <div class="table-responsive">
              <table class="table mb-0">
                <thead>
                  <tr><th>Time</th><th>Bin ID</th><th>Location</th><th>Status</th><th class="text-end">Action</th></tr>
                </thead>
                <tbody id="recentAlertsBody">
                  <?php if (empty($recent_alerts)): ?>
                    <tr><td colspan="5" class="text-center py-4 text-muted">No recent alerts</td></tr>
                  <?php else: foreach ($recent_alerts as $a): ?>
                    <tr>
                      <td><?php echo htmlspecialchars($a['last_emptied'] ?? $a['updated_at'] ?? $a['created_at'] ?? 'N/A'); ?></td>
                      <td><strong><?php echo htmlspecialchars($a['bin_code'] ?? $a['bin_id']); ?></strong></td>
                      <td><?php echo htmlspecialchars($a['location'] ?? ''); ?></td>
                      <td>
                        <?php
                          $s = $a['status'] ?? '';
                          $display = match(strtolower($s)) {
                            'full' => 'Full',
                            'empty' => 'Empty',
                            'half_full' => 'Half Full',
                            'needs_attention' => 'Needs Attention',
                            'out_of_service' => 'Out of Service',
                            default => $s
                          };
                          $badge = (strtolower($s) === 'full') ? 'danger' : ((strtolower($s) === 'empty') ? 'success' : ((strtolower($s) === 'half_full') ? 'warning' : 'secondary'));
                        ?>
                        <span class="badge bg-<?php echo $badge; ?>"><?php echo htmlspecialchars($display); ?></span>
                      </td>
                      <td class="text-end">
                        <a href="janitor-assigned-bins.php" class="btn btn-sm btn-soft-primary">Manage</a>
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
      function escapeHtml(s) {
        if (s === null || s === undefined) return '';
        return String(s)
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#039;');
      }

      async function loadDashboardData() {
        try {
          const url = new URL(window.location.href);
          url.searchParams.set('action', 'get_dashboard_stats');
          const resp = await fetch(url.toString(), { credentials: 'same-origin' });
          if (!resp.ok) return;
          const data = await resp.json();
          if (!data || !data.success) return;

          // Update stats
          const assignedEl = document.getElementById('assignedBinsCount');
          const pendingEl = document.getElementById('pendingTasksCount');
          const completedEl = document.getElementById('completedTodayCount');
          if (assignedEl) assignedEl.textContent = data.assignedBins ?? 0;
          if (pendingEl) pendingEl.textContent = data.pendingTasks ?? 0;
          if (completedEl) completedEl.textContent = data.completedToday ?? 0;

          // Update recent alerts table
          const alertsTbody = document.getElementById('recentAlertsBody');
          if (!alertsTbody) return;
          alertsTbody.innerHTML = '';
          const alerts = data.bins || [];

          if (!alerts.length) {
            alertsTbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">No recent alerts</td></tr>';
          } else {
            alerts.forEach(b => {
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
              const time = b.last_emptied || b.updated_at || b.created_at || 'N/A';
              const binCode = b.bin_code || b.bin_id || '';
              const location = b.location || '';

              alertsTbody.insertAdjacentHTML('beforeend', `
                <tr>
                  <td>${escapeHtml(time)}</td>
                  <td><strong>${escapeHtml(binCode)}</strong></td>
                  <td>${escapeHtml(location)}</td>
                  <td><span class="badge bg-${meta[0]}">${escapeHtml(meta[1])}</span></td>
                  <td class="text-end"><a href="janitor-assigned-bins.php" class="btn btn-sm btn-soft-primary">Manage</a></td>
                </tr>
              `);
            });
          }
        } catch (err) {
          console.warn('Dashboard refresh error', err);
        }
      }

      document.addEventListener('DOMContentLoaded', function() {
        loadDashboardData();
        setInterval(loadDashboardData, 1000);
      });
    })();
    </script>
  </body>
  </html>
