#!/usr/bin/env python3
"""Fetch teacher (evaluatee) details from the Schoolsie API for many accounts.

For each account in a credentials JSON file:
  1. POST /api/v1/publics/user/login  {"identity": ..., "password": ...}
     -> data.access_token
  2. GET  /api/v1/evaluation/evaluatees?evaluation_session_id=<ID>
     with  Authorization: Bearer <access_token>
     -> data.list = [ {staff_id, staff_name, ...}, ... ]

Everything returned about each teacher is saved as-is into one output
JSON file (deduped by staff_id across accounts), and each teacher's
staff_picture_url photo is downloaded into a local folder (default:
scripts/images/) with a "<staff_id>_<name>.<ext>" filename.

Usage:
    python fetch_teachers.py users.json -o teachers.json --session 12
    python fetch_teachers.py users.json --no-images   # skip photo download

users.json formats accepted (any of):
    [{"identity": "8241860", "password": "kmss"}, ...]
    [{"username": "8241860", "password": "kmss"}, ...]
    {"users": [ ... same as above ... ]}

Cloudflare sits in front of this site and blocks plain Python HTTPS clients
("error 1010: browser signature banned" = TLS fingerprint block). For the
best chance of getting through, install Chrome TLS impersonation first:

    pip install curl_cffi

With it installed the script talks exactly like real desktop Chrome; without
it, it falls back to urllib with full browser headers (often still blocked).

Outbound requests go through the proxy pool in ../proxy.json using the same
logic as proxy.php: random pick among the least-used proxies, its `used` /
`last_used` counters bumped and written back (file-locked). Use --no-proxy to
send direct, --proxy-file to point at another pool.
"""

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    from curl_cffi import requests as _cffi_requests
    HAS_CFFI = True
except ImportError:
    _cffi_requests = None
    HAS_CFFI = False

_CFFI_SESSION = None


def _cffi_session():
    """One shared session impersonating desktop Chrome (TLS + HTTP/2)."""
    global _CFFI_SESSION
    if _CFFI_SESSION is None:
        _CFFI_SESSION = _cffi_requests.Session(impersonate="chrome120")
    return _CFFI_SESSION

BASE_URL = "https://es.schoolsie.com"
LOGIN_PATH = "/api/v1/publics/user/login"
EVALUATEES_PATH = "/api/v1/evaluation/evaluatees"
TIMEOUT = 30
PAUSE_BETWEEN_ACCOUNTS = 1.0  # seconds, be gentle with the server

# Outbound proxy pool — same logic as proxy.php pool_pick_least_used():
# random pick among the least-used proxies, bump used/last_used, write back.
PROXY_FILE = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "proxy.json")
)
USE_POOL = True          # toggled by --no-proxy / --proxy-file
_PROXY_WARNED = False    # only warn once about pool problems


def _lock(fp):
    try:
        if os.name == "nt":
            import msvcrt
            fp.seek(0)
            msvcrt.locking(fp.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        return True
    except Exception:
        return False


def _unlock(fp):
    try:
        if os.name == "nt":
            import msvcrt
            fp.seek(0)
            msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass


def pool_pick_least_used(path=None):
    """Return (proxy_dict | None, warning | None) — mirrors proxy.php."""
    global _PROXY_WARNED
    path = path or PROXY_FILE
    if not os.path.isfile(path):
        return None, "pool empty — add proxies first"
    try:
        fp = open(path, "r+b")
    except OSError as e:
        return None, f"cannot open proxy.json: {e}"
    locked = _lock(fp)
    try:
        raw = fp.read().decode("utf-8", "replace")
        try:
            doc = json.loads(raw) if raw.strip() else None
        except ValueError:
            doc = None
        items = doc.get("proxies") if isinstance(doc, dict) else None
        items = items if isinstance(items, list) else []
        valid = []
        for e in items:
            if isinstance(e, dict) and e.get("host") and e.get("port"):
                e["used"] = int(e.get("used") or 0)
                valid.append(e)
        if not valid:
            return None, "pool empty — add proxies first"
        lo = min(e["used"] for e in valid)
        pick = random.choice([e for e in valid if e["used"] == lo])
        pick["used"] += 1
        pick["last_used"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if locked:
            fp.seek(0)
            fp.truncate()
            fp.write(json.dumps({"proxies": items}, indent=4,
                                ensure_ascii=False).encode("utf-8"))
            fp.flush()
    finally:
        if locked:
            _unlock(fp)
        fp.close()
    return pick, None


def proxy_url(p):
    """curl proxy URL — socks5 uses socks5h (remote DNS) like CURLPROXY_SOCKS5_HOSTNAME."""
    scheme = str(p.get("type") or "http").lower()
    scheme = {"socks5": "socks5h", "socks4": "socks4", "https": "https",
              "http": "http"}.get(scheme, "http")
    auth = ""
    if p.get("user"):
        auth = f"{p['user']}:{p.get('pass') or ''}@"
    return f"{scheme}://{auth}{p['host']}:{int(p['port'])}"


def _pick_proxy(log=False):
    """Pick a pool proxy for this request; returns (url|None, warning|None)."""
    global _PROXY_WARNED
    if not USE_POOL:
        return None, None
    entry, warn = pool_pick_least_used()
    if warn:
        if not _PROXY_WARNED:
            print(f"[!] {warn} — sent direct", flush=True)
            _PROXY_WARNED = True
        return None, warn
    if log:
        print(f"    [~] proxy {entry['host']}:{entry['port']} "
              f"({entry.get('type', 'http')}, used {entry['used']})", flush=True)
    return proxy_url(entry), None


def load_credentials(path):
    """Load + normalize the credentials file into [(identity, password)]."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        for key in ("users", "accounts", "credentials", "data", "list"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            raise ValueError(
                "credentials file must be a list, or an object with a "
                "'users' (or accounts/credentials/data/list) array"
            )
    if not isinstance(raw, list):
        raise ValueError("credentials file must contain a JSON array")
    creds = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            print(f"  [!] entry #{i} is not an object, skipped", flush=True)
            continue
        identity = item.get("identity", item.get("username",
                     item.get("user", item.get("userid", item.get("id", "")))))
        password = item.get("password", item.get("pass", item.get("pwd", "")))
        identity, password = str(identity or ""), str(password or "")
        if not identity or not password:
            print(f"  [!] entry #{i} missing identity/password, skipped", flush=True)
            continue
        creds.append((identity, password))
    return creds


CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
_CH_UA = '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"'

LOGIN_HEADERS = {
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.8",
    "Cache-Control": "no-cache",
    "Content-Type": "application/json",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://es.schoolsie.com/login",
    "Sec-Ch-Ua": _CH_UA,
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": CHROME_UA,
}

LIST_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.8",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Sec-Ch-Ua": _CH_UA,
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": CHROME_UA,
}


def _fail(status, reason, body_text, url):
    raise RuntimeError(f"HTTP {status} {reason} {body_text[:500]}".strip()
                       + f"  [url: {url}]")


def _urllib_open(req, purl):
    if purl:
        scheme = "https" if req.full_url.startswith("https://") else "http"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({scheme: purl}))
        return opener.open(req, timeout=TIMEOUT)
    return urllib.request.urlopen(req, timeout=TIMEOUT)


def api_post_json(url, payload, headers, log_proxy=False):
    purl, _ = _pick_proxy(log=log_proxy)
    if HAS_CFFI:
        try:
            r = _cffi_session().post(url, json=payload, headers=headers,
                                     timeout=TIMEOUT, proxy=purl)
            try:
                data = r.json()
            except Exception:
                data = None
            if r.status_code >= 400:
                _fail(r.status_code, r.reason, r.text or "", url)
            return r.status_code, data
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"network error: {e}")
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with _urllib_open(req, purl) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8")[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"HTTP {e.code} {e.reason} {detail}".strip())
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e.reason}")


def api_get_json(url, headers, log_proxy=False):
    purl, _ = _pick_proxy(log=log_proxy)
    if HAS_CFFI:
        try:
            r = _cffi_session().get(url, headers=headers, timeout=TIMEOUT,
                                    proxy=purl)
            try:
                data = r.json()
            except Exception:
                data = None
            if r.status_code >= 400:
                _fail(r.status_code, r.reason, r.text or "", url)
            return r.status_code, data
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"network error: {e}")
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _urllib_open(req, purl) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8")[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"HTTP {e.code} {e.reason} {detail}".strip())
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e.reason}")



def _safe_name(text, fallback):
    """Filesystem-safe version of a teacher name."""
    cleaned = re.sub(r"[^\w\-. ]+", "", text or "").strip()
    cleaned = re.sub(r"\s+", "_", cleaned)
    return cleaned or fallback


def api_get_bytes(url, referer):
    """Binary GET used for photos; returns bytes (empty on failure)."""
    headers = {
        "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        "Referer": referer,
        "User-Agent": CHROME_UA,
        "Sec-Ch-Ua": _CH_UA,
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "image",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Site": "same-origin",
    }
    purl, _ = _pick_proxy()
    if HAS_CFFI:
        r = _cffi_session().get(url, headers=headers, timeout=TIMEOUT, proxy=purl)
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code} for {url}")
        return r.content
    req = urllib.request.Request(url, headers=headers, method="GET")
    with _urllib_open(req, purl) as resp:
        return resp.read()



def download_photo(teacher, images_dir, session_id):
    """Download staff_picture_url into images_dir; return local path or None.

    Relative URLs like "uploads/foo.jpg" are resolved against BASE_URL.
    Skips files that already exist so re-runs are cheap.
    """
    raw_url = str(teacher.get("staff_picture_url") or "").strip()
    if not raw_url:
        return None
    if raw_url.lower().startswith(("http://", "https://")):
        url = raw_url
    else:
        url = f"{BASE_URL}/{raw_url.lstrip('/')}"

    sid = teacher.get("staff_id", teacher.get("id", "unknown"))
    ext = os.path.splitext(raw_url.split("?")[0])[1] or ".jpg"
    if ext.lower() not in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
        ext = ".jpg"
    name = _safe_name(str(teacher.get("staff_name") or ""), str(sid))
    dest = os.path.join(images_dir, f"{sid}_{name}{ext}")
    if os.path.isfile(dest) and os.path.getsize(dest) > 0:
        return dest

    referer = f"{BASE_URL}/student/student-survey-list/{session_id}"
    try:
        data = api_get_bytes(url, referer)
    except Exception as e:
        print(f"    [!] photo failed ({sid}): {e}", flush=True)
        return None
    if not data:
        return None
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def login(identity, password):
    """Return the access_token for one account."""
    _, data = api_post_json(
        BASE_URL + LOGIN_PATH,
        {"identity": identity, "password": password},
        LOGIN_HEADERS,
        log_proxy=True,
    )
    if isinstance(data, dict) and data.get("errors"):
        raise RuntimeError(f"login rejected: {data['errors']}")
    token = ((data or {}).get("data") or {}).get("access_token")
    if not token:
        raise RuntimeError(f"no access_token in response: {str(data)[:300]}")
    return token


def fetch_evaluatees(access_token, session_id):
    """Return the raw teacher list for one session."""
    headers = dict(LIST_HEADERS)
    headers["Referer"] = (
        f"https://es.schoolsie.com/student/student-survey-list/{session_id}"
    )
    headers["Authorization"] = f"Bearer {access_token}"
    _, data = api_get_json(
        f"{BASE_URL}{EVALUATEES_PATH}?evaluation_session_id={session_id}",
        headers,
    )
    if isinstance(data, dict) and data.get("errors"):
        raise RuntimeError(f"evaluatees rejected: {data['errors']}")
    node = (data or {}).get("data", data)
    if isinstance(node, dict) and isinstance(node.get("list"), list):
        return node["list"]
    if isinstance(node, list):
        return node
    raise RuntimeError(f"unexpected evaluatees shape: {str(data)[:300]}")


def main():
    ap = argparse.ArgumentParser(description="Dump Schoolsie evaluatees for many accounts.")
    ap.add_argument("users_file", help="credentials JSON (see USAGE at top of file)")
    ap.add_argument("-o", "--output", default="teachers.json", help="output JSON file")
    ap.add_argument("--session", default="12", help="evaluation_session_id (default: 12)")
    ap.add_argument("--images",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "images"),
                    help="folder for teacher photos (default: scripts/images)")
    ap.add_argument("--no-images", action="store_true",
                    help="skip downloading staff photos")
    ap.add_argument("--no-proxy", action="store_true",
                    help="send direct — ignore the proxy.json pool")
    ap.add_argument("--proxy-file", default=None,
                    help="proxy pool JSON (default: ../proxy.json)")
    args = ap.parse_args()

    global USE_POOL, PROXY_FILE
    if args.no_proxy:
        USE_POOL = False
    if args.proxy_file:
        PROXY_FILE = os.path.abspath(args.proxy_file)

    creds = load_credentials(args.users_file)
    print(f"[*] {len(creds)} account(s) loaded from {args.users_file}", flush=True)
    if not creds:
        sys.exit("nothing to do — no valid credentials found.")
    if HAS_CFFI:
        print("[*] transport: curl_cffi (Chrome TLS impersonation)", flush=True)
    else:
        print("[!] 'curl_cffi' is NOT installed — Cloudflare will probably "
              "block plain Python (error 1010).", flush=True)
        print("    fix: pip install curl_cffi   (then re-run)", flush=True)
    if USE_POOL:
        try:
            with open(PROXY_FILE, "r", encoding="utf-8") as f:
                n = len((json.load(f).get("proxies") or []))
            print(f"[*] proxy pool: {n} prox(ies) in {PROXY_FILE}", flush=True)
        except Exception as e:
            print(f"[!] proxy pool unavailable ({e}) — sent direct", flush=True)
    else:
        print("[*] proxy pool: disabled (--no-proxy)", flush=True)

    teachers_by_id = {}   # staff_id -> full teacher object (first seen wins)
    order = []            # staff_ids in first-seen order
    accounts = []

    images_dir = None
    if not args.no_images:
        images_dir = args.images
        os.makedirs(images_dir, exist_ok=True)
        print(f"[*] photos -> {images_dir}", flush=True)

    try:
        for n, (identity, password) in enumerate(creds, 1):
            print(f"[*] ({n}/{len(creds)}) login {identity} ...", flush=True)
            try:
                token = login(identity, password)
                teachers = fetch_evaluatees(token, args.session)
                got = 0
                for t in teachers:
                    if not isinstance(t, dict):
                        continue
                    sid = t.get("staff_id", t.get("id"))
                    if sid is None:
                        continue
                    got += 1
                    if sid not in teachers_by_id:
                        teachers_by_id[sid] = t
                        order.append(sid)
                accounts.append({"identity": identity, "ok": True,
                                 "teacher_count": got, "error": None})
                print(f"    [+] {got} teacher(s)", flush=True)
            except Exception as e:  # keep going with the next account
                accounts.append({"identity": identity, "ok": False,
                                 "teacher_count": 0, "error": str(e)})
                print(f"    [-] FAILED: {e}", flush=True)
            if n < len(creds):
                time.sleep(PAUSE_BETWEEN_ACCOUNTS)
    except KeyboardInterrupt:
        print("\n[!] interrupted by user — saving partial results...", flush=True)

    downloaded = failed = 0
    if images_dir:
        print(f"[*] downloading photos for {len(order)} teacher(s)...", flush=True)
        for sid in order:
            teacher = teachers_by_id[sid]
            local = download_photo(teacher, images_dir, args.session)
            if local:
                teacher["local_image_path"] = local
                downloaded += 1
                print(f"    [+] {os.path.basename(local)}", flush=True)
            elif str(teacher.get("staff_picture_url") or "").strip():
                failed += 1
            time.sleep(0.2)

    result = {
        "evaluation_session_id": args.session,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "accounts_total": len(creds),
        "accounts_ok": sum(1 for a in accounts if a["ok"]),
        "teacher_count": len(order),
        "images_dir": images_dir,
        "images_downloaded": downloaded,
        "images_failed": failed,
        "accounts": accounts,
        "teachers": [teachers_by_id[sid] for sid in order],
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[*] done: {result['teacher_count']} unique teacher(s), "
          f"{result['accounts_ok']}/{result['accounts_total']} account(s) ok "
          f"-> {args.output}", flush=True)


if __name__ == "__main__":
    main()
