<?php
// Proxy pool manager — stores outbound proxies in proxy.json (same folder).
//
//   List (credentials masked): GET  proxies.php?action=list
//   Import txt/json         : POST {"action":"import","format":"auto|txt|json","data":"..."}
//   Delete one              : POST {"action":"delete","id":"..."}
//   Clear all               : POST {"action":"clear"}
//   Reset usage counters    : POST {"action":"reset_usage"}
//
// proxy.json shape:
//   {"proxies":[{"id","type","host","port","user","pass","used","last_used","added_at"}]}
// Accepted TXT lines (one per line, # = comment):
//   http://user:pass@host:port   https://host:port   socks5://host:port
//   socks4://host:port           host:port   user:pass@host:port   host:port:user:pass
// Accepted JSON: array of strings (same as TXT), array of objects
//   {type,host,port,user,pass}  {url:"http://..."}  or {proxies:[...]}

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

define('PROXY_FILE', __DIR__ . '/proxy.json');

function pool_read_raw() {
    if (!file_exists(PROXY_FILE)) return [];
    $d = json_decode(@file_get_contents(PROXY_FILE) ?: '', true);
    if (is_array($d) && isset($d['proxies']) && is_array($d['proxies'])) return array_values($d['proxies']);
    if (is_array($d) && function_exists('array_is_list') && array_is_list($d)) return array_values($d);
    return [];
}
function pool_write_raw($list) {
    $tmp = PROXY_FILE . '.tmp';
    if (@file_put_contents($tmp, json_encode(['proxies' => array_values($list)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return false;
    return @rename($tmp, PROXY_FILE);
}
// Public view: credentials never leave the server except the username.
function pool_public($list) {
    $out = [];
    foreach ($list as $e) {
        if (!is_array($e)) continue;
        $out[] = [
            'id' => (string)($e['id'] ?? ''),
            'type' => strtolower((string)($e['type'] ?? 'http')),
            'host' => (string)($e['host'] ?? ''),
            'port' => (int)($e['port'] ?? 0),
            'user' => (string)($e['user'] ?? ''),
            'has_pass' => !empty($e['pass']),
            'used' => (int)($e['used'] ?? 0),
            'last_used' => $e['last_used'] ?? null,
            'added_at' => $e['added_at'] ?? null,
        ];
    }
    return $out;
}
function pool_new_id() { try { return 'p' . bin2hex(random_bytes(6)); } catch (Throwable $t) { return 'p' . uniqid(); } }
function pool_norm_type($s) {
    $s = strtolower(trim((string)$s));
    if ($s === 'http') return 'http';
    if ($s === 'https') return 'https';
    if ($s === 'socks4' || $s === 'socks4a') return 'socks4';
    if ($s === 'socks5' || $s === 'socks5h') return 'socks5';
    return false;
}
function pool_default_port($t) { return ($t === 'socks4' || $t === 'socks5') ? 1080 : 8080; }
function pool_make($type, $host, $port, $user, $pass) {
    $host = trim((string)$host); $port = (int)$port;
    if ($host === '' || $port < 1 || $port > 65535) return [null, 'bad host/port'];
    return [[
        'id' => pool_new_id(), 'type' => $type, 'host' => $host, 'port' => $port,
        'user' => trim((string)$user), 'pass' => (string)$pass,
        'used' => 0, 'last_used' => null, 'added_at' => gmdate('c'),
    ], null];
}
function pool_parse_line($line) {
    $line = trim((string)$line);
    if ($line === '' || $line[0] === '#' || substr($line, 0, 2) === '//') return [null, null];
    // scheme://[user:pass@]host:port
    if (preg_match('#^[a-z0-9]+://#i', $line)) {
        $p = @parse_url($line);
        if (!$p || empty($p['host'])) return [null, 'bad url: ' . $line];
        $t = pool_norm_type($p['scheme'] ?? 'http');
        if (!$t) return [null, 'unsupported scheme in: ' . $line];
        return pool_make($t, $p['host'], $p['port'] ?? pool_default_port($t),
            isset($p['user']) ? urldecode($p['user']) : '', isset($p['pass']) ? urldecode($p['pass']) : '');
    }
    // user:pass@host:port
    if (preg_match('/^([^:@\s]+):([^@\s]+)@(\[[^\]]+\]|[^:\s\]]+):(\d+)$/', $line, $m))
        return pool_make('http', trim($m[3], '[]'), $m[4], $m[1], $m[2]);
    // host:port:user:pass
    if (preg_match('/^(\[[^\]]+\]|[^:\s\]]+):(\d+):([^:\s]+):(\S+)$/', $line, $m))
        return pool_make('http', trim($m[1], '[]'), $m[2], $m[3], $m[4]);
    // host:port
    if (preg_match('/^(\[[^\]]+\]|[^:\s\]]+):(\d+)$/', $line, $m))
        return pool_make('http', trim($m[1], '[]'), $m[2], '', '');
    return [null, 'unrecognized: ' . $line];
}
function pool_from_object($o) {
    if (!is_array($o)) return [null, 'bad entry'];
    if (isset($o['url']) || isset($o['proxy'])) return pool_parse_line((string)($o['url'] ?? $o['proxy']));
    $host = $o['host'] ?? $o['ip'] ?? $o['server'] ?? $o['address'] ?? '';
    if (trim((string)$host) === '') return [null, 'missing host'];
    $t = pool_norm_type($o['type'] ?? $o['scheme'] ?? $o['protocol'] ?? 'http') ?: 'http';
    return pool_make($t, $host, $o['port'] ?? pool_default_port($t),
        $o['user'] ?? $o['username'] ?? $o['login'] ?? '', $o['pass'] ?? $o['password'] ?? '');
}
function pool_key($e) {
    return strtolower((string)$e['type']) . '|' . strtolower((string)$e['host']) . '|' . (int)$e['port'] . '|' . strtolower((string)($e['user'] ?? ''));
}

// ---------- dispatch ----------
$action = $_GET['action'] ?? null;
$input = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input');
    $input = json_decode($raw ?: '', true);
    if (!is_array($input)) $input = $_POST;
    if ($action === null) $action = $input['action'] ?? null;
}

if ($action === 'list' || ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === null)) {
    echo json_encode(['proxies' => pool_public(pool_read_raw())]);
    exit;
}

if ($action === 'import') {
    $format = strtolower((string)($input['format'] ?? 'auto'));
    $data = (string)($input['data'] ?? '');
    if (strlen($data) > 2 * 1024 * 1024) { http_response_code(400); echo json_encode(['error' => 'Payload too large (max 2MB).']); exit; }
    $entries = []; $errors = [];
    $asJson = ($format === 'json') || ($format === 'auto' && preg_match('/^\s*[\[{]/', $data));
    if ($asJson) {
        $j = json_decode($data, true);
        if ($j === null && trim($data) !== 'null') { http_response_code(400); echo json_encode(['error' => 'Invalid JSON.']); exit; }
        if (is_array($j) && (isset($j['proxies']) || isset($j['list']) || isset($j['data']) || isset($j['items'])))
            $j = $j['proxies'] ?? $j['list'] ?? $j['data'] ?? $j['items'];
        $items = is_array($j) ? (array_is_list($j) ? $j : [$j]) : [];
        foreach ($items as $it) {
            if (is_string($it)) [$e, $err] = pool_parse_line($it);
            elseif (is_array($it)) [$e, $err] = pool_from_object($it);
            else { $e = null; $err = 'bad entry'; }
            if ($e) $entries[] = $e; elseif ($err) $errors[] = $err;
        }
    } else {
        foreach (preg_split('/\r\n|\n|\r/', $data) as $ln) {
            [$e, $err] = pool_parse_line($ln);
            if ($e) $entries[] = $e; elseif ($err) $errors[] = $err;
        }
    }
    $list = pool_read_raw();
    $seen = []; foreach ($list as $e) if (is_array($e)) $seen[pool_key($e)] = true;
    $added = 0; $skipped = 0;
    foreach ($entries as $e) {
        $k = pool_key($e);
        if (isset($seen[$k])) { $skipped++; continue; }
        $seen[$k] = true; $list[] = $e; $added++;
    }
    if (!pool_write_raw($list)) { http_response_code(500); echo json_encode(['error' => 'Cannot write proxy.json — check folder permissions.']); exit; }
    echo json_encode(['added' => $added, 'skipped' => $skipped, 'total' => count($list),
        'errors' => array_slice($errors, 0, 5), 'proxies' => pool_public($list)]);
    exit;
}

define('PROXY_SOURCE_URL', 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text');

if ($action === 'refresh') {
    // Pull the latest free list, REPLACE the pool, but keep `used` counts
    // (and ids) for proxies that appear in both old and new lists.
    $src = trim((string)($input['source'] ?? PROXY_SOURCE_URL));
    if ($src === '') $src = PROXY_SOURCE_URL;
    if (!filter_var($src, FILTER_VALIDATE_URL) || !in_array(strtolower((string)parse_url($src, PHP_URL_SCHEME)), ['http', 'https'], true)) {
        http_response_code(400); echo json_encode(['error' => 'Invalid source URL.']); exit;
    }
    if (!function_exists('curl_init')) { http_response_code(500); echo json_encode(['error' => 'PHP cURL extension is not enabled.']); exit; }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $src);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
    curl_setopt($ch, CURLOPT_TIMEOUT, 25);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'minimal-api-client/1.0');
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $cerr = curl_error($ch);
    curl_close($ch);
    if ($body === false || $body === '' || $code < 200 || $code >= 300) {
        http_response_code(502);
        echo json_encode(['error' => 'Could not fetch proxy source (HTTP ' . $code . '): ' . ($cerr ?: 'empty response')]);
        exit;
    }
    if (strlen($body) > 2 * 1024 * 1024) { http_response_code(502); echo json_encode(['error' => 'Source response too large.']); exit; }
    $entries = [];
    foreach (preg_split('/\r\n|\n|\r/', $body) as $ln) {
        [$e, $errLine] = pool_parse_line($ln);
        if ($e) $entries[] = $e;
    }
    // dedupe fresh list, keep first-seen order
    $uniq = []; $seenNew = [];
    foreach ($entries as $e) { $k = pool_key($e); if (!isset($seenNew[$k])) { $seenNew[$k] = true; $uniq[] = $e; } }
    $old = pool_read_raw();
    $oldByKey = [];
    foreach ($old as $e) if (is_array($e)) $oldByKey[pool_key($e)] = $e;
    $final = []; $kept = 0; $added = 0;
    foreach ($uniq as $e) {
        $k = pool_key($e);
        if (isset($oldByKey[$k])) { $final[] = $oldByKey[$k]; $kept++; }  // repeat: keep id + used count
        else { $final[] = $e; $added++; }                                 // new: starts at used 0
    }
    if (!pool_write_raw($final)) { http_response_code(500); echo json_encode(['error' => 'Cannot write proxy.json.']); exit; }
    echo json_encode(['refreshed' => true, 'added' => $added, 'kept' => $kept,
        'dropped' => count($old) - $kept, 'total' => count($final), 'proxies' => pool_public($final)]);
    exit;
}

if ($action === 'delete') {
    $id = (string)($input['id'] ?? '');
    $list = array_values(array_filter(pool_read_raw(), function ($e) use ($id) {
        return is_array($e) && ($e['id'] ?? '') !== $id;
    }));
    if (!pool_write_raw($list)) { http_response_code(500); echo json_encode(['error' => 'Cannot write proxy.json.']); exit; }
    echo json_encode(['deleted' => true, 'total' => count($list), 'proxies' => pool_public($list)]);
    exit;
}

if ($action === 'clear') {
    if (!pool_write_raw([])) { http_response_code(500); echo json_encode(['error' => 'Cannot write proxy.json.']); exit; }
    echo json_encode(['cleared' => true, 'total' => 0, 'proxies' => []]);
    exit;
}

if ($action === 'reset_usage') {
    $list = pool_read_raw();
    foreach ($list as &$e) if (is_array($e)) { $e['used'] = 0; $e['last_used'] = null; }
    unset($e);
    if (!pool_write_raw($list)) { http_response_code(500); echo json_encode(['error' => 'Cannot write proxy.json.']); exit; }
    echo json_encode(['reset' => true, 'total' => count($list), 'proxies' => pool_public($list)]);
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'Unknown action. Use list/import/delete/clear/reset_usage/refresh.']);
