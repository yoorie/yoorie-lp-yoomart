<?php
// YooMart done-for-you lead handler: validates, stores (SQLite + CSV outside the web root), emails support.
declare(strict_types=1);
const LEAD_TO = 'support@yoorie.com';
$dir = getenv('LEADS_DIR') ?: '/home/u635857887/yoorie-leads';   // outside public_html
header('X-Robots-Tag: noindex'); header('Cache-Control: no-store');
$wantsJson = str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json');
function out(int $code, array $body, bool $json): never {
    http_response_code($code);
    if ($json) { header('Content-Type: application/json'); echo json_encode($body); exit; }
    header('Location: ./?'.($body['ok'] ?? false ? 'sent=1' : 'error=1').'#lead'); exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') out(405, ['ok' => false, 'error' => 'POST only'], true);
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$xff = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')[0]);
if (filter_var($xff, FILTER_VALIDATE_IP)) $ip = $xff;

// honeypot: pretend success
if (trim((string) ($_POST['website'] ?? '')) !== '') out(200, ['ok' => true], $wantsJson);

$clean = fn (string $k, int $max) => mb_substr(trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string) ($_POST[$k] ?? ''))), 0, $max);
$lead = [
    'name' => $clean('name', 80), 'phone' => $clean('phone', 20), 'city' => $clean('city', 60),
    'business' => $clean('business', 60), 'budget' => $clean('budget', 40),
    'message' => mb_substr(trim(str_replace("\0", '', (string) ($_POST['message'] ?? ''))), 0, 1000),
    'source' => $clean('src', 500),
];
$digits = preg_replace('/\D/', '', $lead['phone']);
if ($lead['name'] === '' || $lead['city'] === '' || $lead['business'] === '' || $lead['budget'] === '') out(422, ['ok' => false, 'error' => 'Please fill in all required fields.'], $wantsJson);
if (strlen($digits) < 10 || strlen($digits) > 13) out(422, ['ok' => false, 'error' => 'Please enter a valid phone / WhatsApp number.'], $wantsJson);

umask(0077);
if (! is_dir($dir)) { @mkdir($dir, 0700, true); }
@chmod($dir, 0700);
try {
    $db = new PDO('sqlite:'.$dir.'/leads.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $db->exec('CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY, created_at TEXT, name TEXT, phone TEXT, city TEXT, business TEXT, budget TEXT, message TEXT, source TEXT, ip TEXT, ua TEXT, mailed INTEGER DEFAULT 0)');
    $db->exec('CREATE TABLE IF NOT EXISTS hits (ip TEXT, at INTEGER)');
    $now = time();
    $db->prepare('DELETE FROM hits WHERE at < ?')->execute([$now - 3600]);
    $c = $db->prepare('SELECT COUNT(*) FROM hits WHERE ip = ? AND at > ?'); $c->execute([$ip, $now - 600]);
    $p = $db->prepare('SELECT COUNT(*) FROM leads WHERE phone = ? AND created_at > ?'); $p->execute([$lead['phone'], gmdate('c', $now - 600)]);
    if ((int) $c->fetchColumn() >= 5 || (int) $p->fetchColumn() >= 2) out(429, ['ok' => false, 'error' => 'Too many requests. Please wait a few minutes or WhatsApp us.'], $wantsJson);
    $db->prepare('INSERT INTO hits (ip, at) VALUES (?, ?)')->execute([$ip, $now]);
    $at = gmdate('c');
    $db->prepare('INSERT INTO leads (created_at, name, phone, city, business, budget, message, source, ip, ua) VALUES (?,?,?,?,?,?,?,?,?,?)')
       ->execute([$at, ...array_values($lead), $ip, mb_substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 250)]);
    $id = (int) $db->lastInsertId();
    @chmod($dir.'/leads.sqlite', 0600);
} catch (Throwable $e) { error_log('lead db: '.$e->getMessage()); $id = 0; $at = gmdate('c'); }

// CSV backup (formula-injection safe)
$csv = $dir.'/leads.csv'; $new = ! is_file($csv);
if ($fh = @fopen($csv, 'ab')) {
    flock($fh, LOCK_EX);
    if ($new) fputcsv($fh, ['id', 'created_at_utc', 'name', 'phone', 'city', 'business', 'budget', 'message', 'source', 'ip']);
    fputcsv($fh, array_map(fn ($v) => preg_match('/^[=+\-@\t]/', (string) $v) ? "'".$v : $v, [$id, $at, ...array_values($lead), $ip]));
    flock($fh, LOCK_UN); fclose($fh); @chmod($csv, 0600);
}

$body = "New YooMart done-for-you enquiry\n\n";
foreach (['Name' => 'name', 'Phone/WhatsApp' => 'phone', 'City' => 'city', 'Business type' => 'business', 'Budget' => 'budget', 'Message' => 'message', 'Source' => 'source'] as $l => $k) $body .= str_pad($l.':', 16).$lead[$k]."\n";
$body .= "\nWhatsApp: https://wa.me/".(strlen($digits) === 10 ? '91'.$digits : $digits)."\nLead #$id · ".gmdate('Y-m-d H:i')." UTC · IP $ip\n";
$subj = '=?UTF-8?B?'.base64_encode('New lead: '.$lead['name'].' ('.$lead['city'].')').'?=';
$headers = "From: YooMart Leads <no-reply@yoorie.com>\r\nContent-Type: text/plain; charset=UTF-8\r\nX-Mailer: yoorie-lead";
$mailed = function_exists('mail') && @mail(LEAD_TO, $subj, $body, $headers, '-fno-reply@yoorie.com');
if ($mailed && $id && isset($db)) $db->prepare('UPDATE leads SET mailed = 1 WHERE id = ?')->execute([$id]);
out(200, ['ok' => true, 'id' => $id], $wantsJson);
