<?php
// minimal api client — PHP CORS / network proxy
// POST JSON: { "url": "https://...", "method": "GET", "headers": {...}, "body": "..." }
// Returns JSON: { "status": 200, "statusText": "", "headers": {...}, "body": "...", "isBase64": false, "time_ms": 123 }

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Health check: GET proxy.php with no body -> usage info (also lets UI test availability)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && empty(file_get_contents('php://input'))) {
    echo json_encode(['ok' => true, 'proxy' => 'php-cors-proxy', 'usage' => 'POST JSON {url, method, headers, body}']);
    exit;
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON payload. Expected {url, method, headers, body}.']);
    exit;
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

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
curl_setopt($ch, CURLOPT_HTTPHEADER, $outHeaders);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);            // include response headers in output
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_ENCODING, '');            // accept gzip/deflate, auto-decode

if ($body !== null && $body !== '' && in_array($method, ['POST','PUT','PATCH','DELETE','OPTIONS'], true)) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, (string)$body);
} elseif ($method === 'HEAD') {
    curl_setopt($ch, CURLOPT_NOBODY, true);
}

$start = microtime(true);
$rawResp = curl_exec($ch);
$elapsedMs = (int)round((microtime(true) - $start) * 1000);

if ($rawResp === false) {
    http_response_code(502);
    echo json_encode(['error' => 'Upstream request failed: ' . curl_error($ch), 'url' => $url]);
    curl_close($ch);
    exit;
}

$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$status     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
curl_close($ch);

$headerStr = substr($rawResp, 0, $headerSize);
$respBody  = substr($rawResp, $headerSize);

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
if (!mb_check_encoding($respBody, 'UTF-8')) {
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
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
