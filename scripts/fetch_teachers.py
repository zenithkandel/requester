#!/usr/bin/env python3
"""Fetch teacher (evaluatee) details from the Schoolsie API for many accounts.

For each account in a credentials JSON file:
  1. POST /api/v1/publics/user/login  {"identity": ..., "password": ...}
     -> data.access_token
  2. GET  /api/v1/evaluation/evaluatees?evaluation_session_id=<ID>
     with  Authorization: Bearer <access_token>
     -> data.list = [ {staff_id, staff_name, ...}, ... ]

Everything returned about each teacher is saved as-is into one output
JSON file (deduped by staff_id across accounts).

Usage:
    python fetch_teachers.py users.json -o teachers.json --session 12

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
"""

import argparse
import json
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


def api_post_json(url, payload, headers):
    if HAS_CFFI:
        try:
            r = _cffi_session().post(url, json=payload, headers=headers,
                                     timeout=TIMEOUT)
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
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8")[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"HTTP {e.code} {e.reason} {detail}".strip())
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e.reason}")


def api_get_json(url, headers):
    if HAS_CFFI:
        try:
            r = _cffi_session().get(url, headers=headers, timeout=TIMEOUT)
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
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8")[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"HTTP {e.code} {e.reason} {detail}".strip())
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e.reason}")


def login(identity, password):
    """Return the access_token for one account."""
    _, data = api_post_json(
        BASE_URL + LOGIN_PATH,
        {"identity": identity, "password": password},
        LOGIN_HEADERS,
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
    args = ap.parse_args()

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

    teachers_by_id = {}   # staff_id -> full teacher object (first seen wins)
    order = []            # staff_ids in first-seen order
    accounts = []

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

    result = {
        "evaluation_session_id": args.session,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "accounts_total": len(creds),
        "accounts_ok": sum(1 for a in accounts if a["ok"]),
        "teacher_count": len(order),
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
