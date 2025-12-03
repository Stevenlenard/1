# Session Management Testing Guide

## Test Case 1: Fresh Login Flow ✅
1. Open browser → Go to `http://localhost/ok-main/`
2. Should see **index landing page** (no redirect)
3. Click **Login** button → Role modal appears
4. Click **User Login** → Goes to user-login.php
5. Fill in janitor email & password
6. Click **Sign In**
7. ✅ Should redirect to **janitor-dashboard.php**

## Test Case 2: Persistent Session (Stay Logged In) ✅
1. After Test Case 1 (you're on dashboard)
2. Copy-paste index.php link in address bar
3. ✅ Should see **index landing page** (NOT redirect)
4. Copy-paste user-login.php in address bar
5. ✅ Should automatically redirect to **janitor-dashboard.php** (because already logged in)
6. Copy-paste admin-dashboard.php in address bar
7. ✅ Should stay on **admin-dashboard.php** or redirect (protected page)

## Test Case 3: Proper Logout Flow 🔑
1. While on dashboard, click **Logout** button
2. Should see logout modal
3. Confirm logout
4. ✅ Should redirect to **index page**
5. Verify: No dashboard buttons/links appear
6. Click **Login** → Shows role modal (fresh start)
7. Try janitor login again
8. ✅ Should show **login form** (NOT auto-redirect to dashboard)
9. Fill credentials
10. ✅ Should redirect to **janitor-dashboard.php** (NEW fresh session)

## Test Case 4: Session Expiry After Logout 🚫
1. After logout (Test Case 3)
2. Try going directly to janitor-dashboard.php
3. ✅ Should redirect to **user-login.php** (no active session)
4. Try going directly to admin-dashboard.php
5. ✅ Should redirect to **admin-login.php** (no active session)

## Expected Behavior Summary

| Action | Expected Result |
|--------|-----------------|
| Fresh load index.php | Show index (no redirect) |
| Click login, fill form, submit | Redirect to dashboard |
| Logged in, visit index.php | Show index (no redirect) |
| Logged in, visit user-login.php | Redirect to dashboard |
| Click logout, confirm | Redirect to index |
| After logout, visit user-login.php | Show login form |
| After logout, visit dashboard | Redirect to login page |
| After logout, submit login form | NEW session created → dashboard |

## Debug URLs
- Check session status: Look at browser cookies (DevTools → Application → Cookies)
- Look for `auth_token` cookie
- After logout, `auth_token` should be gone
- After fresh login, `auth_token` should be new

## If Something Goes Wrong
1. Check browser console (F12) for errors
2. Check XAMPP error logs: `xampp/apache/logs/error.log`
3. Check if cookies are being set: DevTools → Network tab → Response headers
4. Clear browser cookies manually and try again
