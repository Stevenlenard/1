<?php
// Reusable helpers for creating janitor_alerts from any script.
// Usage: include_once __DIR__ . '/janitor-alerts-functions.php';
// then call create_alert_for_bin($bin_id, $title, $message, $notification_id = null, $forceInsert = false);

if (!function_exists('ensure_janitor_alerts_table')) {
    function ensure_janitor_alerts_table() {
        global $pdo, $conn;
        $exists = false;
        try {
            if (isset($pdo) && $pdo instanceof PDO) {
                $r = $pdo->query("SHOW TABLES LIKE 'janitor_alerts'");
                $exists = ($r && $r->rowCount() > 0);
            } else {
                $r = $conn->query("SHOW TABLES LIKE 'janitor_alerts'");
                $exists = ($r && $r->num_rows > 0);
            }
        } catch (Exception $e) {
            $exists = false;
        }
        if ($exists) return;
        $sql = "
          CREATE TABLE IF NOT EXISTS janitor_alerts (
            alert_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            notification_id INT NULL,
            janitor_id INT NULL,
            bin_id INT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT,
            is_read TINYINT(1) NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX (janitor_id),
            INDEX (bin_id),
            INDEX (notification_id)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ";
        if (isset($pdo) && $pdo instanceof PDO) {
            $pdo->exec($sql);
        } else {
            $conn->query($sql);
        }
    }
}

if (!function_exists('insert_janitor_alert')) {
    /**
     * Insert a janitor_alert. By default performs duplicate prevention.
     * When $forceInsert === true it will always insert (no dedupe).
     *
     * $opts keys: notification_id|null, janitor_id, bin_id|null, title, message, is_read (0/1)
     */
    function insert_janitor_alert(array $opts, bool $forceInsert = false) {
        global $pdo, $conn;

        $notification_id = $opts['notification_id'] ?? null;
        $janitor_id = isset($opts['janitor_id']) ? (int)$opts['janitor_id'] : null;
        $bin_id = isset($opts['bin_id']) ? (int)$opts['bin_id'] : null;
        $title = $opts['title'] ?? '';
        $message = $opts['message'] ?? '';
        $is_read = isset($opts['is_read']) ? (int)$opts['is_read'] : 0;

        try {
            // ensure table exists
            ensure_janitor_alerts_table();

            if (!$forceInsert) {
                // Duplicate prevention
                if ($notification_id && $janitor_id) {
                    if (isset($pdo) && $pdo instanceof PDO) {
                        $p = $pdo->prepare("SELECT alert_id FROM janitor_alerts WHERE notification_id = :nid AND janitor_id = :jid LIMIT 1");
                        $p->execute([':nid' => $notification_id, ':jid' => $janitor_id]);
                        if ($p->fetch()) return null;
                    } else {
                        $s = $conn->prepare("SELECT alert_id FROM janitor_alerts WHERE notification_id = ? AND janitor_id = ? LIMIT 1");
                        if ($s) {
                            $s->bind_param("ii", $notification_id, $janitor_id);
                            $s->execute();
                            $res = $s->get_result();
                            if ($res && $res->fetch_assoc()) { $s->close(); return null; }
                            $s->close();
                        }
                    }
                }

                // Avoid repeating identical title for same janitor/bin within 24 hours
                if ($bin_id && $janitor_id) {
                    $since = date('Y-m-d H:i:s', time() - 24*3600);
                    if (isset($pdo) && $pdo instanceof PDO) {
                        $p = $pdo->prepare("SELECT alert_id FROM janitor_alerts WHERE janitor_id = :jid AND bin_id = :bid AND title = :title AND created_at >= :since LIMIT 1");
                        $p->execute([':jid' => $janitor_id, ':bid' => $bin_id, ':title' => $title, ':since' => $since]);
                        if ($p->fetch()) return null;
                    } else {
                        $s = $conn->prepare("SELECT alert_id FROM janitor_alerts WHERE janitor_id = ? AND bin_id = ? AND title = ? AND created_at >= ? LIMIT 1");
                        if ($s) {
                            $s->bind_param("iiss", $janitor_id, $bin_id, $title, $since);
                            $s->execute();
                            $res = $s->get_result();
                            if ($res && $res->fetch_assoc()) { $s->close(); return null; }
                            $s->close();
                        }
                    }
                }
            }

            // Insert the alert
            if (isset($pdo) && $pdo instanceof PDO) {
                $ins = $pdo->prepare("INSERT INTO janitor_alerts (notification_id, janitor_id, bin_id, title, message, is_read, created_at) VALUES (:nid, :jid, :bid, :title, :msg, :isread, NOW())");
                $ins->execute([
                    ':nid' => $notification_id,
                    ':jid' => $janitor_id,
                    ':bid' => $bin_id,
                    ':title' => $title,
                    ':msg' => $message,
                    ':isread' => $is_read
                ]);
                return (int)$pdo->lastInsertId();
            } else {
                $nidVal = $notification_id !== null ? intval($notification_id) : 'NULL';
                $jidVal = $janitor_id !== null ? intval($janitor_id) : 'NULL';
                $bidVal = $bin_id !== null ? intval($bin_id) : 'NULL';
                $titleEsc = $conn->real_escape_string($title);
                $msgEsc = $conn->real_escape_string($message);
                $isReadVal = intval($is_read);
                $sql = "INSERT INTO janitor_alerts (notification_id, janitor_id, bin_id, title, message, is_read, created_at) VALUES ({$nidVal}, {$jidVal}, {$bidVal}, '{$titleEsc}', '{$msgEsc}', {$isReadVal}, NOW())";
                $conn->query($sql);
                return $conn->insert_id ?? null;
            }
        } catch (Exception $e) {
            error_log("[janitor_alerts] insert error: " . $e->getMessage());
            return null;
        }
    }
}

if (!function_exists('create_alert_for_bin')) {
    /**
     * Convenience: creates an alert for a bin's assigned janitor (if assigned).
     * Pass $forceInsert = true to always insert (skip dedupe).
     */
    function create_alert_for_bin(int $bin_id, string $title, string $message, $notification_id = null, bool $forceInsert = false) {
        global $pdo, $conn;
        // resolve assigned janitor
        $assigned = null;
        try {
            if (isset($pdo) && $pdo instanceof PDO) {
                $s = $pdo->prepare("SELECT assigned_to FROM bins WHERE bin_id = ? LIMIT 1");
                $s->execute([$bin_id]);
                $r = $s->fetch(PDO::FETCH_ASSOC);
                if ($r) $assigned = $r['assigned_to'] ?? null;
            } else {
                $res = $conn->query("SELECT assigned_to FROM bins WHERE bin_id = " . intval($bin_id) . " LIMIT 1");
                if ($res && $row = $res->fetch_assoc()) $assigned = $row['assigned_to'] ?? null;
            }
        } catch (Exception $e) {
            // ignore
        }
        if (empty($assigned)) return null;
        ensure_janitor_alerts_table();
        return insert_janitor_alert([
            'notification_id' => $notification_id,
            'janitor_id' => (int)$assigned,
            'bin_id' => (int)$bin_id,
            'title' => $title,
            'message' => $message,
            'is_read' => 0
        ], $forceInsert);
    }
}