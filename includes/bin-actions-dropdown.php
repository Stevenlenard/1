<?php
/**
 * Bin Actions Dropdown Component
 * Renders a standalone "More Actions" dropdown menu for a bin row.
 * This is a reusable component that can be included in any table or list view.
 * 
 * Usage:
 * <?php include_once __DIR__ . '/bin-actions-dropdown.php'; ?>
 * Then call: renderBinActionsDropdown($bin_id, $bin_status);
 */

function renderBinActionsDropdown($bin_id, $bin_status = 'empty') {
    $reactivateText = ($bin_status === 'disabled') ? 'Reactivate Bin' : 'Deactivate Bin';
    
    echo '
    <div class="bin-actions-dropdown">
        <div class="btn-group dropdown" role="group">
            <button 
                type="button" 
                class="btn btn-soft-dark btn-sm dropdown-toggle" 
                id="binActionsBtn_' . htmlspecialchars($bin_id) . '" 
                data-bs-toggle="dropdown" 
                data-bs-popper-config="{&quot;modifiers&quot;:[{&quot;name&quot;:&quot;offset&quot;,&quot;options&quot;:{&quot;offset&quot;:[0,10]}}]}"
                aria-expanded="false" 
                title="More Actions"
                data-bin-id="' . htmlspecialchars($bin_id) . '"
            >
                <i class="bi bi-three-dots-vertical"></i>
            </button>
            
            <ul 
                class="dropdown-menu dropdown-menu-end bin-actions-menu" 
                id="binActionsMenu_' . htmlspecialchars($bin_id) . '"
                aria-labelledby="binActionsBtn_' . htmlspecialchars($bin_id) . '"
                data-bin-id="' . htmlspecialchars($bin_id) . '"
                data-bin-status="' . htmlspecialchars($bin_status) . '"
            >
                <!-- Status Management Section -->
                <li class="dropdown-header">Status Management</li>
                <li>
                    <a class="dropdown-item bin-action-item" href="#" data-action="edit-status" data-bin-id="' . htmlspecialchars($bin_id) . '">
                        <i class="bi bi-pencil-fill me-2"></i>Edit Status
                    </a>
                </li>
                <li>
                    <a class="dropdown-item bin-action-item" href="#" data-action="toggle-active" data-bin-id="' . htmlspecialchars($bin_id) . '" data-bin-status="' . htmlspecialchars($bin_status) . '">
                        <i class="bi bi-slash-circle me-2"></i>' . htmlspecialchars($reactivateText) . '
                    </a>
                </li>
                <li>
                    <a class="dropdown-item bin-action-item" href="#" data-action="view-history" data-bin-id="' . htmlspecialchars($bin_id) . '">
                        <i class="bi bi-clock-history me-2"></i>View History
                    </a>
                </li>
                
                <li><hr class="dropdown-divider"></li>
                
                <!-- Sensor Management Section -->
                <li class="dropdown-header">Sensor Management</li>
                <li>
                    <a class="dropdown-item bin-action-item" href="#" data-action="calibrate-sensor" data-bin-id="' . htmlspecialchars($bin_id) . '">
                        <i class="bi bi-sliders me-2"></i>Calibrate Sensor
                    </a>
                </li>
                
                <li><hr class="dropdown-divider"></li>
                
                <!-- Notifications Section -->
                <li class="dropdown-header">Notifications</li>
                <li>
                    <a class="dropdown-item bin-action-item" href="#" data-action="send-notification" data-bin-id="' . htmlspecialchars($bin_id) . '">
                        <i class="bi bi-bell-fill me-2"></i>Send Notification
                    </a>
                </li>
                
                <li><hr class="dropdown-divider"></li>
                
                <!-- Bin Information Section -->
                <li class="dropdown-header">Bin Information</li>
                <li>
                    <a class="dropdown-item bin-action-item" href="#" data-action="edit-details" data-bin-id="' . htmlspecialchars($bin_id) . '">
                        <i class="bi bi-pencil-square me-2"></i>Edit Details
                    </a>
                </li>
                
                <li><hr class="dropdown-divider"></li>
                
                <!-- Danger Zone -->
                <li>
                    <a class="dropdown-item text-danger bin-action-item" href="#" data-action="delete" data-bin-id="' . htmlspecialchars($bin_id) . '">
                        <i class="bi bi-trash me-2"></i>Delete Bin
                    </a>
                </li>
            </ul>
        </div>
    </div>
    ';
}
?>
