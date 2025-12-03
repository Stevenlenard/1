/**
 * Bin Actions Dropdown Component JavaScript
 * Handles all dropdown menu item clicks and delegates to appropriate action handlers
 * Uses Bootstrap's Popper.js for smart positioning to stay in viewport
 */

(function() {
  'use strict';

  // Wait for DOM to be ready
  document.addEventListener('DOMContentLoaded', function() {
    initBinActionsDropdown();
  });

  /**
   * Initialize bin actions dropdown event handlers
   */
  function initBinActionsDropdown() {
    // Setup each dropdown with Popper.js positioning
    document.addEventListener('shown.bs.dropdown', function(e) {
      const button = e.target.querySelector('.dropdown-toggle');
      const menu = e.target.querySelector('.dropdown-menu');
      
      if (!button || !menu) return;
      
      // Allow Bootstrap's Popper.js to position the dropdown
      // This will automatically keep it within viewport bounds
      try {
        // Bootstrap 5 uses Popper.js v2
        const dropdown = new bootstrap.Dropdown(button);
      } catch (err) {
        console.warn('Bootstrap dropdown initialization:', err);
      }
    });

    // Delegate click handler for all dropdown items
    document.addEventListener('click', function(e) {
      const actionItem = e.target.closest('.bin-action-item');
      if (!actionItem) return;

      e.preventDefault();
      e.stopPropagation();

      const action = actionItem.getAttribute('data-action');
      const binId = actionItem.getAttribute('data-bin-id');
      const binStatus = actionItem.getAttribute('data-bin-status') || 'empty';

      if (!binId) {
        console.error('Bin ID not found in action item');
        return;
      }

      // Route to appropriate handler
      switch (action) {
        case 'edit-status':
          if (typeof openEditStatus === 'function') {
            openEditStatus(e, parseInt(binId));
          } else {
            console.error('openEditStatus function not found');
          }
          break;

        case 'toggle-active':
          if (typeof confirmToggleActive === 'function') {
            confirmToggleActive(e, parseInt(binId), binStatus);
          } else {
            console.error('confirmToggleActive function not found');
          }
          break;

        case 'view-history':
          if (typeof openHistory === 'function') {
            openHistory(e, parseInt(binId));
          } else {
            console.error('openHistory function not found');
          }
          break;

        case 'calibrate-sensor':
          if (typeof openCalibrate === 'function') {
            openCalibrate(e, parseInt(binId));
          } else {
            console.error('openCalibrate function not found');
          }
          break;

        case 'send-notification':
          if (typeof openNotify === 'function') {
            openNotify(e, parseInt(binId));
          } else {
            console.error('openNotify function not found');
          }
          break;

        case 'edit-details':
          if (typeof openEditBin === 'function') {
            openEditBin(e, parseInt(binId));
          } else {
            console.error('openEditBin function not found');
          }
          break;

        case 'delete':
          if (typeof confirmDelete === 'function') {
            confirmDelete(e, parseInt(binId));
          } else {
            console.error('confirmDelete function not found');
          }
          break;

        default:
          console.warn('Unknown action:', action);
      }

      // Close the dropdown after action
      closeDropdownForBin(binId);
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
      if (e.target.closest('.bin-actions-dropdown')) return;
      
      document.querySelectorAll('.bin-actions-dropdown .dropdown-menu.show').forEach(menu => {
        menu.classList.remove('show');
        const btn = menu.previousElementSibling;
        if (btn) btn.setAttribute('aria-expanded', 'false');
      });
    });
  }

  /**
   * Close dropdown for a specific bin
   */
  function closeDropdownForBin(binId) {
    const menu = document.getElementById('binActionsMenu_' + binId);
    if (menu) {
      menu.classList.remove('show');
      const btn = document.getElementById('binActionsBtn_' + binId);
      if (btn) btn.setAttribute('aria-expanded', 'false');
    }
  }

  // Expose function to global scope if needed
  window.closeDropdownForBin = closeDropdownForBin;
})();
