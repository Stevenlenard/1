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

// AJAX GET endpoints for profile
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action'])) {
    header('Content-Type: application/json; charset=utf-8');

    // Janitor profile data
    if ($_GET['action'] === 'get_profile') {
        $profile = null;
        try {
            $stmt = $conn->prepare("SELECT janitor_id, first_name, last_name, phone, email FROM janitors WHERE janitor_id = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param("i", $janitorId);
                $stmt->execute();
                $res = $stmt->get_result();
                $profile = $res->fetch_assoc();
                $stmt->close();
            }
        } catch (Exception $e) { /* ignore */ }

        echo json_encode(['success' => true, 'profile' => $profile]);
        exit;
    }
}
// end GET endpoints

// Fetch initial profile data
$displayName = 'Janitor';
$profilePicSrc = '';
$assignedBins = 0;
$pendingTasks = 0;

try {
    $janitorProfile = null;
    if (!empty($janitorId)) {
        if (isset($pdo) && $pdo instanceof PDO) {
            $stmt = $pdo->prepare("SELECT first_name, last_name, profile_picture FROM janitors WHERE janitor_id = ? LIMIT 1");
            $stmt->execute([(int)$janitorId]);
            $janitorProfile = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
        } else {
            if ($stmt = $conn->prepare("SELECT first_name, last_name, profile_picture FROM janitors WHERE janitor_id = ? LIMIT 1")) {
                $stmt->bind_param("i", $janitorId);
                $stmt->execute();
                $res = $stmt->get_result();
                $janitorProfile = $res ? $res->fetch_assoc() : null;
                $stmt->close();
            }
        }
    }
    if (!empty($janitorProfile)) {
        $displayName = trim((($janitorProfile['first_name'] ?? '') . ' ' . ($janitorProfile['last_name'] ?? '')));
        if (!empty($janitorProfile['profile_picture'])) {
            $profilePicSrc = $janitorProfile['profile_picture'];
        }
    }
} catch (Exception $e) {
    // ignore
}

if (empty($displayName)) $displayName = 'Janitor';
if (empty($profilePicSrc)) {
    $profilePicSrc = 'https://ui-avatars.com/api/?name=' . urlencode($displayName) . '&background=0D6EFD&color=fff&size=150';
}

// Get assigned bins and pending tasks
try {
    if ($janitorId > 0) {
        $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId));
        if ($r && $row = $r->fetch_assoc()) $assignedBins = intval($row['c'] ?? 0);

        $r = $conn->query("SELECT COUNT(*) AS c FROM bins WHERE assigned_to = " . intval($janitorId) . " AND (bins.status = 'full' OR (bins.capacity IS NOT NULL AND bins.capacity >= 100))");
        if ($r && $row = $r->fetch_assoc()) $pendingTasks = intval($row['c'] ?? 0);
    }
} catch (Exception $e) {
    // ignore
}

// Update session name for consistency
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$_SESSION['name'] = $displayName;
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>My Profile - Trashbin Management</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <link rel="stylesheet" href="css/bootstrap.min.css">
  <link rel="stylesheet" href="css/janitor-dashboard.css">
  <link rel="stylesheet" href="css/janitor-profile.css">

  <!-- New: overrides for circular avatar + matching accent -->
  <style>
      /* make avatar perfectly circular and consistent size */
      .profile-picture-wrapper {
        width: 150px;
        height: 150px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
        /* soft green glow similar to other pages */
        background: radial-gradient(circle at 30% 30%, rgba(25,183,115,0.10), rgba(255,255,255,0));
        box-shadow: 0 18px 40px rgba(11,142,93,0.08);
        overflow: visible;
      }

      .profile-picture {
        width: 120px;
        height: 120px;
        border-radius: 50%;
        object-fit: cover;
        border: 6px solid rgba(25,183,115,0.09); /* subtle ring consistent with accent */
        box-shadow: 0 10px 30px rgba(11,142,93,0.06);
        display:block;
      }

      /* camera button: circular with green gradient consistent with other pages */
      .profile-edit-btn {
        position: absolute;
        right: -6px;
        bottom: -6px;
        width: 48px;
        height: 48px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(180deg, #36d38f 0%, #12b36b 100%);
        border: none;
        color: #fff;
        box-shadow: 0 8px 22px rgba(11,142,93,0.12);
        cursor: pointer;
      }
      .profile-edit-btn i { font-size: 18px; }

      /* profile header accent: subtle green top border and lighter background */
      .profile-header-card {
        border-top: 4px solid #1aa86d;
        background: linear-gradient(180deg, rgba(246,255,250,0.94), rgba(255,255,255,0.96));
        border-radius: 12px;
        padding: 28px;
      }

      .profile-header-content { display:flex; gap:28px; align-items:center; }
      .profile-info .profile-name { color: #0b7a52; font-weight:700; font-size: 28px; margin:0; }
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
      <a href="janitor-assigned-bins.php" class="sidebar-item">
        <i class="fa-solid fa-trash-alt"></i><span>Assigned Bins</span>
      </a>
      <a href="janitor-alerts.php" class="sidebar-item">
        <i class="fa-solid fa-bell"></i><span>Alerts</span>
      </a>
      <a href="janitor-profile.php" class="sidebar-item active">
        <i class="fa-solid fa-user"></i><span>My Profile</span>
      </a>
    </aside>

    <!-- Main content -->
    <main class="content">
      <div class="section-header">
        <div>
          <h1 class="page-title">My Profile</h1>
          <p class="page-subtitle">Manage your personal information and settings</p>
        </div>
      </div>

      <div class="profile-container">
        <!-- Profile Header Card -->
        <div class="profile-header-card">
          <div class="profile-header-content">
            <div class="profile-picture-wrapper">
              <img id="profileImg" src="<?php echo $profilePicSrc; ?>" alt="Profile Picture" class="profile-picture">
              <input type="file" id="photoInput" accept=".png,.jpg,.jpeg" style="display:none;">
              <button type="button" class="profile-edit-btn" id="changePhotoBtn" title="Change Photo"><i class="fa-solid fa-camera"></i></button>
            </div>
            <div class="profile-info">
              <h2 class="profile-name" id="profileName"><?php echo htmlspecialchars($displayName); ?></h2>
              <p class="profile-role">Maintenance Staff</p>
              <div id="photoMessage" class="validation-message"></div>
            </div>
          </div>
        </div>

        <div class="profile-content-grid">
          <div class="profile-sidebar">
            <div class="profile-stats-card">
              <h6 class="stats-title">Quick Stats</h6>
              <div class="stat-item">
                <span class="stat-label">Assigned Bins</span>
                <span class="stat-value" id="profileAssignedBinsCount"><?php echo intval($assignedBins); ?></span>
              </div>
              <div class="stat-item">
                <span class="stat-label">Pending Tasks</span>
                <span class="stat-value" id="profilePendingTasksCount"><?php echo intval($pendingTasks); ?></span>
              </div>
              <div class="stat-item">
                <span class="stat-label">Member Since</span>
                <span class="stat-value"><?php echo date('Y'); ?></span>
              </div>
            </div>

            <div class="profile-menu-card">
              <h6 class="menu-title">Settings</h6>
              <a href="#personal-info" class="profile-menu-item active" onclick="showProfileTab('personal-info', this); return false;">
                <i class="fa-solid fa-user"></i>
                <span>Personal Info</span>
              </a>
              <a href="#change-password" class="profile-menu-item" onclick="showProfileTab('change-password', this); return false;">
                <i class="fa-solid fa-key"></i>
                <span>Change Password</span>
              </a>
            </div>
          </div>

          <div class="profile-main">
            <div class="tab-content">
              <div class="tab-pane fade show active" id="personal-info">
                <div class="profile-form-card">
                  <div class="form-card-header">
                    <h5><i class="fa-solid fa-user-circle me-2"></i>Personal Information</h5>
                  </div>
                  <div class="form-card-body">
                  <div id="personalInfoAlert" class="validation-message" style="display:none;"></div>
                    <form id="personalInfoForm">
                      <input type="hidden" id="profileJanitorId" name="user_id" value="<?php echo $janitorId; ?>">
                      <div class="form-row">
                        <div class="form-group">
                          <label class="form-label">First Name</label>
                          <input type="text" class="form-control" id="profileFirstName" name="first_name" required>
                          <div class="validation-message"></div>
                        </div>
                        <div class="form-group">
                          <label class="form-label">Last Name</label>
                          <input type="text" class="form-control" id="profileLastName" name="last_name" required>
                          <div class="validation-message"></div>
                        </div>
                      </div>
                      <div class="form-group">
                        <label class="form-label">Email</label>
                        <input type="email" class="form-control" id="profileEmail" name="email" required>
                        <div class="validation-message"></div>
                      </div>
                      <div class="form-group">
                        <label class="form-label">Phone Number</label>
                        <input type="tel" class="form-control" id="profilePhone" name="phone">
                        <div class="validation-message"></div>
                      </div>
                      <button type="button" class="btn btn-primary btn-lg" id="saveProfileBtn"><i class="fa-solid fa-save me-2"></i>Save</button>
                    </form>
                  </div>
                </div>
              </div>

              <div class="tab-pane fade" id="change-password">
                <div class="profile-form-card">
                  <div class="form-card-header">
                    <h5><i class="fa-solid fa-lock me-2"></i>Change Password</h5>
                  </div>
                  <div class="form-card-body">
                    <div id="passwordAlert" class="alert alert-message" style="display:none"></div>
                    <form id="changePasswordForm">
                      <input type="hidden" name="action" value="change_password">
                      <div class="form-group">
                        <label class="form-label">Current Password</label>
                        <div class="password-input-container">
                          <input type="password" class="form-control password-input" id="currentPassword" name="current_password" placeholder="Enter current password" required>
                          <button type="button" class="password-toggle-btn" data-target="#currentPassword"><i class="fa-solid fa-eye"></i></button>
                        </div>
                        <div class="validation-message"></div>
                      </div>
                      <div class="form-group">
                        <label class="form-label">New Password</label>
                        <div class="password-input-container">
                          <input type="password" class="form-control password-input" id="newPassword" name="new_password" placeholder="Enter new password" required>
                          <button type="button" class="password-toggle-btn" data-target="#newPassword"><i class="fa-solid fa-eye"></i></button>
                        </div>
                        <div class="validation-message"></div>
                      </div>
                      <div class="form-group">
                        <label class="form-label">Confirm Password</label>
                        <div class="password-input-container">
                          <input type="password" class="form-control password-input" id="confirmNewPassword" name="confirm_password" placeholder="Confirm new password" required>
                          <button type="button" class="password-toggle-btn" data-target="#confirmNewPassword"><i class="fa-solid fa-eye"></i></button>
                        </div>
                        <div class="validation-message"></div>
                      </div>
                      <button type="submit" class="btn btn-primary btn-lg" id="changePasswordBtn"><i class="fa-solid fa-lock me-2"></i>Update</button>
                    </form>
                  </div>
                </div>
              </div>
            </div>
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

    function escapeHtml(s) {
      if (s === null || s === undefined) return '';
      return String(s)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    // Profile loader
    async function loadProfile() {
      try {
        const resp = await fetch(window.location.pathname + '?action=get_profile', { credentials: 'same-origin' });
        if (!resp.ok) throw new Error('Network error');
        const json = await resp.json();
        if (!json.success || !json.profile) {
          document.getElementById('profileFirstName').value = '';
          document.getElementById('profileLastName').value = '';
          document.getElementById('profilePhone').value = '';
          document.getElementById('profileEmail').value = '';
          return;
        }
        const p = json.profile;
        document.getElementById('profileFirstName').value = p.first_name || '';
        document.getElementById('profileLastName').value = p.last_name || '';
        document.getElementById('profilePhone').value = p.phone || '';
        document.getElementById('profileEmail').value = p.email || '';
      } catch (e) {
        console.warn('Failed to load profile', e);
      }
    }

    // Profile saver
    async function saveProfile() {
      try {
        const first_name = document.getElementById('profileFirstName').value.trim();
        const last_name = document.getElementById('profileLastName').value.trim();
        const phone = document.getElementById('profilePhone').value.trim();
        const email = document.getElementById('profileEmail') ? document.getElementById('profileEmail').value.trim() : '';
        const janitor_id = document.getElementById('profileJanitorId').value;
        const alertEl = document.getElementById('personalInfoAlert');
        
        // Clear previous messages
        if (alertEl) { alertEl.style.display = 'none'; alertEl.textContent = ''; }
        
        // Client-side validation
        if (!first_name) {
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = 'First name is required.';
            alertEl.style.display = 'block';
          }
          return;
        }
        if (/\d/.test(first_name)) {
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = 'First name cannot contain numbers.';
            alertEl.style.display = 'block';
          }
          return;
        }
        
        if (!last_name) {
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = 'Last name is required.';
            alertEl.style.display = 'block';
          }
          return;
        }
        if (/\d/.test(last_name)) {
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = 'Last name cannot contain numbers.';
            alertEl.style.display = 'block';
          }
          return;
        }
        
        if (!email) {
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = 'Email is required.';
            alertEl.style.display = 'block';
          }
          return;
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = 'Invalid email address format.';
            alertEl.style.display = 'block';
          }
          return;
        }
        
        if (phone) {
          const phoneDigits = phone.replace(/\D/g, '');
          if (phoneDigits.length !== 11) {
            if (alertEl) {
              alertEl.className = 'validation-message text-danger';
              alertEl.textContent = 'Phone number must be exactly 11 digits.';
              alertEl.style.display = 'block';
            }
            return;
          }
        }
        
        const formData = new URLSearchParams();
        formData.append('action', 'update_profile');
        formData.append('first_name', first_name);
        formData.append('last_name', last_name);
        formData.append('phone', phone);
        formData.append('email', email);
        formData.append('scope', 'janitor');
        if (janitor_id) formData.append('user_id', janitor_id);

        const resp = await fetch('profile.php', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type':'application/x-www-form-urlencoded'},
          body: formData.toString()
        });
        const json = await resp.json();
        if (json && json.success) {
          if (alertEl) {
            alertEl.className = 'validation-message text-success';
            alertEl.textContent = json.message || 'Successfully updated!';
            alertEl.style.display = 'block';
          }
          try {
            const newName = first_name + ' ' + last_name;
            const nEl = document.getElementById('profileName');
            if (nEl) nEl.textContent = newName;
          } catch (e) { }
          loadProfile();
        } else {
          const msg = (json && json.message) ? json.message : 'Failed to update profile';
          if (alertEl) {
            alertEl.className = 'validation-message text-danger';
            alertEl.textContent = msg;
            alertEl.style.display = 'block';
          }
        }
      } catch (e) {
        console.error('Save profile error', e);
        const alertEl = document.getElementById('personalInfoAlert');
        if (alertEl) {
          alertEl.className = 'validation-message text-danger';
          alertEl.textContent = 'Server error while updating profile';
          alertEl.style.display = 'block';
        }
      }
    }

    document.addEventListener('DOMContentLoaded', function() {
      // Wire profile form submit
      const personalForm = document.getElementById('personalInfoForm');
      if (personalForm) {
        personalForm.addEventListener('submit', function(e) {
          e.preventDefault();
          saveProfile();
        });
      }

      // Photo upload handling
      const changePhotoBtn = document.getElementById('changePhotoBtn');
      const photoInput = document.getElementById('photoInput');
      const profileImg = document.getElementById('profileImg');
      const photoMessage = document.getElementById('photoMessage');
      if (changePhotoBtn && photoInput) {
        changePhotoBtn.addEventListener('click', function() { photoInput.click(); });
        photoInput.addEventListener('change', function() {
          const file = this.files && this.files[0];
          if (!file) return;
          const fd = new FormData();
          fd.append('profile_picture', file);
          fd.append('scope', 'janitor');
          const profileJanitorIdEl = document.getElementById('profileJanitorId');
          if (profileJanitorIdEl && profileJanitorIdEl.value) fd.append('user_id', profileJanitorIdEl.value);
          if (photoMessage) { photoMessage.textContent = 'Uploading...'; photoMessage.style.display = 'block'; }
          fetch('janitor-upload-profile.php', { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(r => r.json())
            .then(data => {
              if (data && data.success && data.path) {
                const ts = new Date().getTime();
                if (profileImg) profileImg.src = data.path + '?t=' + ts;
                if (photoMessage) { photoMessage.textContent = 'Profile picture updated'; photoMessage.className = 'validation-message text-success'; }
                photoInput.value = ''; 
              } else {
                if (photoMessage) { photoMessage.textContent = 'Upload failed: ' + (data && data.message ? data.message : 'Unknown'); photoMessage.className = 'validation-message text-danger'; }
              }
            }).catch(err => {
              console.warn('Photo upload error', err);
              if (photoMessage) { photoMessage.textContent = 'Upload error'; photoMessage.className = 'validation-message text-danger'; }
            });
        });
      }

      // Change password handler
      const changePassForm = document.getElementById('changePasswordForm');
      if (changePassForm) {
        changePassForm.addEventListener('submit', function(e) {
          e.preventDefault();
          const btn = document.getElementById('changePasswordBtn');
          if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Updating'; }
          const formData = new URLSearchParams(new FormData(changePassForm));
          fetch('api/change-janitor-password.php', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: formData.toString()
          }).then(r => r.json()).then(json => {
            const alertEl = document.getElementById('passwordAlert');
            if (json && json.success) {
              if (alertEl) { alertEl.className = 'validation-message text-success'; alertEl.textContent = json.message || 'Password updated'; alertEl.style.display = 'block'; }
              changePassForm.reset();
            } else {
              const msg = (json && json.message) ? json.message : 'Failed to update password';
              if (alertEl) { alertEl.className = 'validation-message text-danger'; alertEl.textContent = msg; alertEl.style.display = 'block'; }
              else alert(msg);
            }
          }).catch(err => {
            console.warn('change password error', err);
            alert('Server error while changing password');
          }).finally(() => {
            if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-lock me-2"></i>Update'; }
          });
        });
      }

      // Save profile button click
      const saveBtn = document.getElementById('saveProfileBtn');
      if (saveBtn) {
        saveBtn.addEventListener('click', function(e) {
          e.preventDefault();
          saveProfile();
        });
      }

      loadProfile();
    });

    // Tab switcher
    window.showProfileTab = function(tabName, el) {
      document.querySelectorAll('.tab-pane').forEach(tab => tab.classList.remove('show','active'));
      const tab = document.getElementById(tabName);
      if (tab) tab.classList.add('show','active');
      document.querySelectorAll('.profile-menu-item').forEach(item => item.classList.remove('active'));
      if (el) el.classList.add('active');
    };

  })();
  </script>
  <script src="js/scroll-progress.js"></script>
  <script src="js/password-toggle.js"></script>
</body>
</html>
