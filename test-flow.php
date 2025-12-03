<!DOCTYPE html>
<html>
<head>
    <title>Session Flow Tester</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
        .box { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #007bff; }
        .success { border-left-color: #28a745; background: #f1f8f4; }
        .warning { border-left-color: #ffc107; background: #fffbf0; }
        .error { border-left-color: #dc3545; background: #fff5f5; }
        h1 { color: #333; }
        h2 { color: #555; margin-top: 30px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #0056b3; }
        code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        .flow { background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🔄 Complete Session Flow Test</h1>
    
    <div class="box success">
        <h2>Step 1: Login</h2>
        <p>Go to: <code>user-login.php</code></p>
        <p>✅ Should show LOGIN FORM (no auto-redirect)</p>
        <p>✅ Fill email & password</p>
        <p>✅ Click Sign In</p>
        <div class="flow">
            <strong>What happens:</strong><br>
            • login-handler.php validates credentials<br>
            • createAuthSession() runs:<br>
            &nbsp;&nbsp;- Inserts record in auth_sessions<br>
            &nbsp;&nbsp;- Sets is_active = 1 ✅<br>
            &nbsp;&nbsp;- Returns auth_token<br>
            • Sets auth_token cookie<br>
            • Redirects to janitor-dashboard.php
        </div>
        <button onclick="goTo('user-login.php')">Go to Login</button>
    </div>
    
    <div class="box success">
        <h2>Step 2: Verify Session Created</h2>
        <p>Go to: <code>debug-session.php</code></p>
        <p>✅ Should show: Session Active: YES</p>
        <p>✅ Should show: User Type: JANITOR</p>
        <p>✅ Database should show: is_active = 1 ✅</p>
        <button onclick="goTo('debug-session.php')">Check Session</button>
    </div>
    
    <div class="box warning">
        <h2>Step 3: Logout</h2>
        <p>Go to: <code>janitor-dashboard.php</code></p>
        <p>✅ Click Logout button in top-right</p>
        <p>✅ Modal appears: "Confirm Logout"</p>
        <p>✅ Click "Yes, Logout"</p>
        <div class="flow">
            <strong>What happens:</strong><br>
            • confirmLogout() runs<br>
            • Redirects to logout-confirm.php<br>
            • logout-confirm.php:<br>
            &nbsp;&nbsp;- UPDATE auth_sessions SET is_active = 0 ✅<br>
            &nbsp;&nbsp;- Destroys $_SESSION<br>
            &nbsp;&nbsp;- Deletes auth_token cookie<br>
            &nbsp;&nbsp;- Sets no-cache headers<br>
            • Redirects to index.php
        </div>
        <button onclick="goTo('janitor-dashboard.php')">Go to Dashboard</button>
    </div>
    
    <div class="box error">
        <h2>Step 4: After Logout - Check Database</h2>
        <p>Go to: <code>debug-session.php</code></p>
        <p>✅ Should show: Session Active: NO</p>
        <p>✅ Database should show: is_active = 0 ❌</p>
        <p>✅ auth_token cookie should be GONE</p>
        <button onclick="goTo('debug-session.php')">Check Session</button>
    </div>
    
    <div class="box error">
        <h2>Step 5: Try Dashboard Without Login</h2>
        <p>Try going directly to: <code>janitor-dashboard.php</code></p>
        <p>✅ Should redirect to user-login.php (because isJanitor() = false)</p>
        <button onclick="goTo('janitor-dashboard.php')">Try Dashboard</button>
    </div>
    
    <div class="box success">
        <h2>Step 6: Login Again - Should Show Form</h2>
        <p>Go to: <code>user-login.php</code></p>
        <p>✅ Should show LOGIN FORM (not auto-redirect!)</p>
        <p>✅ This is the critical test!</p>
        <p>If it auto-redirects to dashboard: PROBLEM!</p>
        <p>If it shows login form: ✅ WORKING!</p>
        <div class="flow">
            <strong>Why it works:</strong><br>
            • config.php loads<br>
            • validateAndRestoreSession() called<br>
            • Query: WHERE token_hash = ? AND is_active = 1<br>
            • Result: NO MATCH (is_active = 0)<br>
            • Returns false<br>
            • isJanitor() = false<br>
            • Login form SHOWS ✅
        </div>
        <button onclick="goTo('user-login.php')">Go to Login</button>
    </div>
    
    <div class="box success">
        <h2>Step 7: Login Again - Fresh Session</h2>
        <p>✅ Fill email & password</p>
        <p>✅ Click Sign In</p>
        <p>✅ Should go to janitor-dashboard.php</p>
        <div class="flow">
            <strong>What happens:</strong><br>
            • NEW auth_sessions record created<br>
            • NEW is_active = 1 ✅<br>
            • NEW auth_token cookie<br>
            • FRESH SESSION with new timestamp
        </div>
    </div>
    
    <div class="box success">
        <h2>Step 8: Verify Fresh Session</h2>
        <p>Go to: <code>debug-session.php</code></p>
        <p>✅ Should show: Session Active: YES</p>
        <p>✅ Should show: is_active = 1</p>
        <p>✅ created_at should be NEW (just now)</p>
        <p>✅ Session is FRESH, not restored ✅</p>
        <button onclick="goTo('debug-session.php')">Check Session</button>
    </div>
    
    <hr style="margin: 40px 0;">
    
    <div class="box">
        <h2>Database Check</h2>
        <p>Login to phpMyAdmin and check auth_sessions table:</p>
        <div style="background: white; padding: 10px; border-radius: 4px; margin-top: 10px;">
            <strong>After logout:</strong><br>
            SELECT * FROM auth_sessions WHERE user_id = 11;<br>
            → Should show: is_active = <code style="color: red;">0</code> ❌
        </div>
        <div style="background: white; padding: 10px; border-radius: 4px; margin-top: 10px;">
            <strong>After login again:</strong><br>
            SELECT * FROM auth_sessions WHERE user_id = 11 ORDER BY created_at DESC LIMIT 1;<br>
            → Should show: is_active = <code style="color: green;">1</code> ✅
        </div>
    </div>
    
    <script>
        function goTo(page) {
            window.location.href = page;
        }
    </script>
</body>
</html>
