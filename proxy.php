<?php
// minimal api client — PHP CORS / network proxy
// POST JSON: { "url": "https://...", "method": "GET", "headers": {...}, "body": "..." }
// Returns JSON: { "status": 200, "statusText": "", "headers": {...}, "body": "...", "isBase64": false, "time_ms": 123 }

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Allow: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// --- Always answer with JSON, even when PHP dies ---
// Without this a fatal error / memory blow-up / timeout becomes the host's HTML 502 page,
// which the client then reports as "proxy.php returned non-JSON".
@set_time_limit(45);
register_shutdown_function(function () {
    $e = error_get_last();
    if (!$e || !in_array((int)$e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) return;
    if (headers_sent()) return;
    http_response_code(500);
    echo json_encode([
        'error' => 'PHP fatal error while proxying: ' . (string)$e['message'],
        'hint'  => 'Usually memory limit exhausted on a big response, or a missing PHP extension (curl/mbstring).',
    ]);
});

$data = null;

// --- Transport 2: GET fallback (used when POST is blocked, e.g. 405 from server) ---
// proxy.php?url=https%3A...&method=POST&headers=%7B...%7D&body=...&body_b64=...
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['url']) && $_GET['url'] !== '') {
    $h = [];
    if (isset($_GET['headers']) && $_GET['headers'] !== '') {
        $decoded = json_decode((string)$_GET['headers'], true);
        if (is_array($decoded)) $h = $decoded;
    }
    $b = null;
    if (isset($_GET['body_b64']) && $_GET['body_b64'] !== '') {
        $tmp = base64_decode((string)$_GET['body_b64'], true);
        $b = ($tmp === false) ? (string)$_GET['body_b64'] : $tmp;
    } elseif (isset($_GET['body'])) {
        $b = (string)$_GET['body'];
    }
    $data = [
        'url'     => (string)$_GET['url'],
        'method'  => isset($_GET['method']) ? (string)$_GET['method'] : 'GET',
        'headers' => $h,
        'body'    => $b,
        'use_pool' => isset($_GET['use_pool']) && !in_array((string)$_GET['use_pool'], ['', '0', 'false', 'no'], true),
    ];
}

// --- Health check: plain GET with no ?url= ---
if ($data === null && $_SERVER['REQUEST_METHOD'] === 'GET' && empty(file_get_contents('php://input'))) {
    echo json_encode(['ok' => true, 'proxy' => 'php-cors-proxy', 'usage' => 'POST JSON {url, method, headers, body} or GET ?url=...&method=...&headers=...&body=...']);
    exit;
}

// --- Transport 1: POST JSON (primary) + form fallback ---
if ($data === null) {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    if (!is_array($data) && isset($_POST['payload'])) {
        $data = json_decode((string)$_POST['payload'], true);
    }
    if (!is_array($data)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON payload. Expected {url, method, headers, body}.']);
        exit;
    }
}

$url    = trim((string)($data['url'] ?? ''));
$method = strtoupper(trim((string)($data['method'] ?? 'GET')));
$headersIn = $data['headers'] ?? [];
$body   = $data['body'] ?? null;

$allowedMethods = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'];
if (!in_array($method, $allowedMethods, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Method not allowed: ' . $method]);
    exit;
}

if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid or missing "url". Include full https:// URL.']);
    exit;
}

$scheme = strtolower(parse_url($url, PHP_URL_SCHEME));
if (!in_array($scheme, ['http','https'], true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Only http:// and https:// URLs are allowed.']);
    exit;
}

// Optional SSRF guard: block localhost-only if ?allow_private=1 is NOT set.
// For a local dev tool we ALLOW private hosts by default, but leave the hook here.
// To enforce blocking, set $BLOCK_PRIVATE = true.
$BLOCK_PRIVATE = false;
if ($BLOCK_PRIVATE) {
    $host = parse_url($url, PHP_URL_HOST);
    $ip = gethostbyname($host);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        http_response_code(403);
        echo json_encode(['error' => 'Blocked private/internal host: ' . $host]);
        exit;
    }
}

function pool_proxy_file() { return __DIR__ . '/proxy.json'; }
function pool_curl_type($t) {
    switch (strtolower((string)$t)) {
        case 'https': return defined('CURLPROXY_HTTPS') ? CURLPROXY_HTTPS : CURLPROXY_HTTP;
        case 'socks4': return CURLPROXY_SOCKS4;
        case 'socks5': return CURLPROXY_SOCKS5_HOSTNAME;
        default: return CURLPROXY_HTTP;
    }
}
// Pick a random proxy among the least-used ones, bump its `used` counter.
// Returns [entry|null, warning|null]. Credentials never leave this file.
function pool_pick_least_used() {
    $f = pool_proxy_file();
    if (!file_exists($f)) return [null, 'pool empty — add proxies first'];
    $fp = @fopen($f, 'c+');
    if (!$fp) return [null, 'cannot open proxy.json'];
    if (!flock($fp, LOCK_EX)) { fclose($fp); return [null, 'cannot lock proxy.json']; }
    $raw = stream_get_contents($fp);
    $d = json_decode($raw ?: '', true);
    $list = (is_array($d) && isset($d['proxies']) && is_array($d['proxies'])) ? array_values($d['proxies']) : [];
    $valid = [];
    foreach ($list as $e) {
        if (!is_array($e) || empty($e['host']) || empty($e['port'])) continue;
        $e['used'] = (int)($e['used'] ?? 0);
        $valid[] = $e;
    }
    if (!$valid) { flock($fp, LOCK_UN); fclose($fp); return [null, 'pool empty — add proxies first']; }
    $min = min(array_column($valid, 'used'));
    $cands = array_values(array_filter($valid, function ($e) use ($min) { return $e['used'] === $min; }));
    $pick = $cands[random_int(0, count($cands) - 1)];
    foreach ($list as &$e) {
        if (is_array($e) && ($e['id'] ?? null) === $pick['id']) {
            $e['used'] = ((int)($e['used'] ?? 0)) + 1;
            $e['last_used'] = gmdate('c');
            $pick = $e;
            break;
        }
    }
    unset($e);
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode(['proxies' => array_values($list)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    fflush($fp); flock($fp, LOCK_UN); fclose($fp);
    return [$pick, null];
}

if (!function_exists('curl_init')) {
    http_response_code(500);
    echo json_encode(['error' => 'PHP cURL extension is not enabled. Enable php_curl in XAMPP.']);
    exit;
}

// Build outgoing headers — drop hop-by-hop / auto headers curl manages itself
$drop = ['host','content-length','connection','transfer-encoding','accept-encoding'];
$outHeaders = [];
if (is_array($headersIn)) {
    foreach ($headersIn as $k => $v) {
        $k = trim((string)$k);
        if ($k === '') continue;
        if (in_array(strtolower($k), $drop, true)) continue;
        // header values must be single-line
        $v = str_replace(["\r","\n"], ' ', (string)$v);
        $outHeaders[] = $k . ': ' . $v;
    }
}

// --- Outbound proxy pool (proxy.json, least-used first) ---
// With the pool on we allow up to 3 tries: free proxies die constantly, and a single dead
// proxy used to burn the whole timeout so the host killed PHP and served its HTML 502 page.
$usePool      = !empty($data['use_pool']);
$maxTries     = $usePool ? 3 : 1;
$proxyUsed    = null;
$proxyWarning = null;
$lastError    = '';
$done         = false;
$tooBig       = false;
$respBody     = '';
$headerStr    = '';
$status       = 0;
$contentType  = null;
$elapsedMs    = 0;

for ($try = 1; $try <= $maxTries; $try++) {
    $poolEntry = null;
    if ($usePool) {
        [$poolEntry, $poolWarn] = pool_pick_least_used();
        if (!$poolEntry) {
            $proxyWarning = $poolWarn ?: 'proxy pool unavailable';
            $lastError    = $proxyWarning;
            break;
        }
    }

    $respBody = '';
    $headerStr = '';
    $tooBig = false;

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL             => $url,
        CURLOPT_CUSTOMREQUEST   => $method,
        CURLOPT_HTTPHEADER      => $outHeaders,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 5,
        CURLOPT_TIMEOUT         => 20,   // keep well under host gateway timeouts
        CURLOPT_CONNECTTIMEOUT  => 5,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_ENCODING        => '',   // accept gzip/deflate, auto-decode
        CURLOPT_LOW_SPEED_LIMIT => 64,   // kill stalled transfers instead of hanging
        CURLOPT_LOW_SPEED_TIME  => 8,
        // Stream instead of RETURNTRANSFER: a multi-MB body used to exhaust memory,
        // crash the worker and surface as the host's HTML 502 page.
        CURLOPT_HEADERFUNCTION  => function ($c, $line) use (&$headerStr, &$respBody) {
            if (preg_match('/^HTTP\/\d/i', $line)) $respBody = ''; // new block (redirect) — drop old body
            $headerStr .= $line;
            return strlen($line);
        },
        CURLOPT_WRITEFUNCTION   => function ($c, $chunk) use (&$respBody, &$tooBig) {
            $respBody .= $chunk;
            if (strlen($respBody) > 4 * 1024 * 1024) { $tooBig = true; return 0; } // abort download
            return strlen($chunk);
        },
    ]);

    if ($poolEntry) {
        curl_setopt($ch, CURLOPT_PROXY, $poolEntry['host'] . ':' . $poolEntry['port']);
        curl_setopt($ch, CURLOPT_PROXYTYPE, pool_curl_type($poolEntry['type'] ?? 'http'));
        if (!empty($poolEntry['user']))
            curl_setopt($ch, CURLOPT_PROXYUSERPWD, $poolEntry['user'] . ':' . ($poolEntry['pass'] ?? ''));
        $proxyUsed = ['id' => $poolEntry['id'] ?? null, 'type' => $poolEntry['type'] ?? 'http',
            'host' => $poolEntry['host'], 'port' => (int)$poolEntry['port'], 'used' => (int)($poolEntry['used'] ?? 0)];
    }

    if ($body !== null && $body !== '' && in_array($method, ['POST','PUT','PATCH','DELETE','OPTIONS'], true)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, (string)$body);
    } elseif ($method === 'HEAD') {
        curl_setopt($ch, CURLOPT_NOBODY, true);
    }

    $start = microtime(true);
    $ok = curl_exec($ch);
    $elapsedMs = (int)round((microtime(true) - $start) * 1000);

    if ($ok !== false && !$tooBig) {
        $status      = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $done = true;
        curl_close($ch);
        break;
    }

    $lastError = $tooBig
        ? 'Upstream response too large (>4MB).'
        : ('attempt ' . $try . '/' . $maxTries . ' failed: ' . (string)curl_error($ch));
    curl_close($ch);
}

if (!$done) {
    http_response_code(502);
    echo json_encode([
        'error'         => 'Upstream request failed — ' . ($lastError ?: 'unknown error'),
        'url'           => $url,
        'proxy_used'    => $proxyUsed,
        'proxy_warning' => $proxyWarning,
        'tries'         => $try - 1,
    ]);
    exit;
}

// If redirects were followed, multiple header blocks are present — keep the last one
$blocks = preg_split('/\r\n\r\n/', trim($headerStr));
$lastHeaders = end($blocks);
$respHeaders = [];
foreach (preg_split('/\r\n/', (string)$lastHeaders) as $i => $line) {
    if ($i === 0) continue; // status line
    $pos = strpos($line, ':');
    if ($pos === false) continue;
    $hk = trim(substr($line, 0, $pos));
    $hv = trim(substr($line, $pos + 1));
    // combine duplicates (e.g. set-cookie)
    if (isset($respHeaders[$hk])) {
        $respHeaders[$hk] .= ', ' . $hv;
    } else {
        $respHeaders[$hk] = $hv;
    }
}
if ($contentType && !isset($respHeaders['content-type']) && !isset($respHeaders['Content-Type'])) {
    $respHeaders['content-type'] = $contentType;
}

// Binary-safe transport: base64 if body is not valid UTF-8 text
$isBase64 = false;
$utf8 = function_exists('mb_check_encoding')
    ? mb_check_encoding($respBody, 'UTF-8')
    : (bool)preg_match('//u', $respBody);
if (!$utf8) {
    $respBody = base64_encode($respBody);
    $isBase64 = true;
}

// Cap payload at ~4MB to avoid blowing up the browser
if (strlen($respBody) > 4 * 1024 * 1024) {
    http_response_code(502);
    echo json_encode(['error' => 'Upstream response too large (>4MB).']);
    exit;
}

echo json_encode([
    'status'     => $status,
    'statusText' => '',
    'headers'    => $respHeaders,
    'body'       => $respBody,
    'isBase64'   => $isBase64,
    'time_ms'    => $elapsedMs,
    'via'        => 'php-proxy',
    'proxy_used' => $proxyUsed,
    'proxy_warning' => $proxyWarning,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
