// js/logout.js - Custom logout modal with beautiful styling

// Create custom logout modal on page load
function createLogoutModal() {
  // Check if modal already exists
  if (document.getElementById('logoutModalOverlay')) return;

  var overlay = document.createElement('div');
  overlay.id = 'logoutModalOverlay';
  overlay.className = 'logout-modal-overlay';
  overlay.innerHTML = `
    <div class="logout-modal-dialog">
      <div class="logout-modal-header">
        <i class="fa-solid fa-right-from-bracket"></i>
        <span>Confirm Logout</span>
      </div>
      <div class="logout-modal-body">
        <p class="logout-modal-message">Are you sure you want to logout?</p>
      </div>
      <div class="logout-modal-footer">
        <button class="logout-btn-cancel" id="logoutBtnCancel">Cancel</button>
        <button class="logout-btn-confirm" id="logoutBtnConfirm">
          <i class="fa-solid fa-check me-2"></i>Logout
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  // Handle cancel
  document.getElementById('logoutBtnCancel').addEventListener('click', function () {
    overlay.classList.remove('active');
  });

  // Handle confirm
  document.getElementById('logoutBtnConfirm').addEventListener('click', function () {
    performLogout();
  });

  // Close on overlay click
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) {
      overlay.classList.remove('active');
    }
  });

  // Close on ESC key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('active')) {
      overlay.classList.remove('active');
    }
  });
}

// Perform logout request
function performLogout() {
  var confirmBtn = document.getElementById('logoutBtnConfirm');
  if (confirmBtn) {
    confirmBtn.disabled = true;
    confirmBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Logging out...';
  }

  fetch('api/logout.php', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Accept': 'application/json'
    }
  })
    .then(function (resp) { return resp.json(); })
    .then(function (data) {
      if (data && data.success) {
        // Redirect to landing/login
        window.location.href = 'index.php';
      } else {
        alert('Logout failed: ' + (data.message || 'unknown error'));
        if (confirmBtn) {
          confirmBtn.disabled = false;
          confirmBtn.innerHTML = '<i class="fa-solid fa-check me-2"></i>Logout';
        }
      }
    })
    .catch(function (err) {
      alert('Logout error: ' + err);
      if (confirmBtn) {
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = '<i class="fa-solid fa-check me-2"></i>Logout';
      }
    });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
  // Create the modal
  createLogoutModal();

  // Attach logout action to any element with the .js-logout-action class
  var els = document.querySelectorAll('.js-logout-action');
  if (!els || els.length === 0) return;

  els.forEach(function (btn) {
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      // Prefer the shared premium modal (#logoutModal) if present (used by janitor dashboard)
      var sharedModal = document.getElementById('logoutModal');
      if (sharedModal) {
        // If the janitor modal helper is present, use it; otherwise toggle class
        if (typeof showLogoutModal === 'function') {
          try { showLogoutModal(e); } catch (err) { sharedModal.classList.add('active'); document.body.style.overflow = 'hidden'; }
        } else {
          sharedModal.classList.add('active');
          document.body.style.overflow = 'hidden';
        }
        return;
      }

      // Fallback to the inline overlay modal
      var overlay = document.getElementById('logoutModalOverlay');
      if (overlay) {
        overlay.classList.add('active');
      }
    });
  });
});

// Attach handlers to the shared premium modal (#logoutModal) if present.
// This removes any inline onclick attributes (which may reference functions
// not present on some pages) and wires Cancel/Confirm to predictable behavior.
function attachSharedModalHandlers() {
  var sharedModal = document.getElementById('logoutModal');
  if (!sharedModal) return;

  try {
    var cancelBtn = sharedModal.querySelector('.btn-cancel');
    var confirmBtn = sharedModal.querySelector('.btn-confirm');

    if (cancelBtn) {
      // Remove inline onclick to avoid ReferenceErrors on pages without janitor JS
      cancelBtn.removeAttribute && cancelBtn.removeAttribute('onclick');
      cancelBtn.addEventListener('click', function (e) {
        e.preventDefault();
        sharedModal.classList.remove('active');
        document.body.style.overflow = '';
      });
    }

    if (confirmBtn) {
      confirmBtn.removeAttribute && confirmBtn.removeAttribute('onclick');
      confirmBtn.addEventListener('click', function (e) {
        e.preventDefault();
        // Use the centralized performLogout() if available to call the API.
        if (typeof performLogout === 'function') {
          performLogout();
        } else {
          // Fallback to the janitor-style redirect if performLogout isn't available
          window.location.href = 'logout-confirm.php';
        }
      });
    }
  } catch (err) {
    console.warn('attachSharedModalHandlers failed', err);
  }
}

// Run attachment early so admin pages behave like janitor pages
document.addEventListener('DOMContentLoaded', attachSharedModalHandlers);
