#!/usr/bin/env python3
"""Standard-library client for the Mindspan apps management API.

Every command writes one JSON result (login also writes a LOGIN_URL event). The
only persistent credential is a refresh token in the operating system's secret
store. This client never writes bearer tokens to a file.
"""

import argparse
import base64
import binascii
import ctypes
import gzip
import hashlib
import http.client
import hmac
import json
import os
import platform
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

VERSION = "0.1.0"
SELF = str(Path(__file__).resolve())
SERVICE = "org.mindspan.apps"
DEFAULT_GOOGLE_CLIENT_ID = "476344853692-fi8170hpm48ojcd83mctvoi6tg4g38ae.apps.googleusercontent.com"
DEFAULT_API_URL = "https://mindspan-apps-api-hiipmf5dta-uc.a.run.app"
OAUTH_CONFIG_URL = "https://apps.at.mindspan.org/oauth-client.json"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
USER_ACTION = {"AUTH_REQUIRED", "AUTH_STORE_LOCKED", "CONFIRMATION_REQUIRED",
               "CONFIG_REQUIRED", "DATA_RULE_REQUIRED", "LINK_CONFIRMATION_REQUIRED"}
MAX_FILES = 20_000
MAX_EXPANDED = 500 * 1024 * 1024
MAX_FILE = 100 * 1024 * 1024
MAX_ARCHIVE = 200 * 1024 * 1024


def envelope(ok, code, message, *, retryable=False, command=None, ask_user=None,
             warnings=None, **data):
    return {
        "ok": ok, "code": code, "message": message, "retryable": retryable,
        "fix": {"command": command, "ask_user": ask_user},
        "warnings": warnings or [], **data,
    }


def emit(body, *, final=True):
    print(json.dumps(body, separators=(",", ":")), flush=True)
    if final:
        raise SystemExit(0 if body["ok"] else 2 if body["code"] in USER_ACTION else 1)


def fail(code, message, *, command=None, ask_user=None, retryable=False, **data):
    emit(envelope(False, code, message, command=command, ask_user=ask_user,
                  retryable=retryable, **data))


def tool_command(args):
    return " ".join(shlex.quote(part) for part in [sys.executable, SELF, *args])


class StoreError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a bearer token to a redirected host."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def store_account(client_id):
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:24]


def _mac_store(account, value=None):
    # `security add-generic-password -w` is not a stdin mode. Framework calls
    # keep credentials out of argv and avoid cross-process Keychain ACL prompts.
    try:
        security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        find = security.SecKeychainFindGenericPassword
        find.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
                         ctypes.c_uint32, ctypes.c_char_p,
                         ctypes.POINTER(ctypes.c_uint32),
                         ctypes.POINTER(ctypes.c_void_p),
                         ctypes.POINTER(ctypes.c_void_p)]
        find.restype = ctypes.c_int32
        add = security.SecKeychainAddGenericPassword
        add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
                        ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
                        ctypes.c_void_p, ctypes.c_void_p]
        add.restype = ctypes.c_int32
        update = security.SecKeychainItemModifyAttributesAndData
        update.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                           ctypes.c_uint32, ctypes.c_void_p]
        update.restype = ctypes.c_int32
        release = core_foundation.CFRelease
        release.argtypes = [ctypes.c_void_p]
        release.restype = None
        service = SERVICE.encode("utf-8")
        user = account.encode("utf-8")

        if value is None:
            password_length = ctypes.c_uint32()
            password_data = ctypes.c_void_p()
            status = find(None, len(service), service, len(user), user,
                          ctypes.byref(password_length), ctypes.byref(password_data), None)
            if status == -25300:  # errSecItemNotFound
                return None
            if status != 0:
                raise StoreError("macOS Keychain is unavailable or locked")
            free_content = security.SecKeychainItemFreeContent
            free_content.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            free_content.restype = ctypes.c_int32
            try:
                return ctypes.string_at(password_data, password_length.value).decode("utf-8") or None
            finally:
                free_content(None, password_data)

        secret = value.encode("utf-8")
        secret_buffer = ctypes.create_string_buffer(secret)
        item = ctypes.c_void_p()
        status = find(None, len(service), service, len(user), user,
                      None, None, ctypes.byref(item))
        if status == 0:
            try:
                status = update(item, None, len(secret), secret_buffer)
            finally:
                release(item)
        elif status == -25300:  # errSecItemNotFound
            status = add(None, len(service), service, len(user), user,
                         len(secret), secret_buffer, None)
        if status != 0:
            raise StoreError("macOS Keychain is unavailable or locked")
    except (OSError, AttributeError, ValueError) as exc:
        raise StoreError("macOS Keychain is unavailable or locked") from exc
    return None


def _linux_store(account, value=None):
    if not shutil.which("secret-tool"):
        raise StoreError("Secret Service is unavailable; install libsecret's secret-tool and unlock the keyring")
    if value is None:
        cmd = ["secret-tool", "lookup", "service", SERVICE, "account", account]
    else:
        cmd = ["secret-tool", "store", "--label=Mindspan apps sign-in",
               "service", SERVICE, "account", account]
    try:
        result = subprocess.run(cmd, input=None if value is None else value,
                                capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoreError("Secret Service is unavailable or locked") from exc
    if result.returncode:
        raise StoreError("Secret Service is unavailable or locked")
    return (result.stdout.strip() or None) if value is None else None


def _windows_store(account, value=None):
    # Windows Credential Manager API, without an external dependency or a file.
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                    ("UserName", wintypes.LPWSTR)]

    advapi = ctypes.WinDLL("Advapi32", use_last_error=True)
    advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    advapi.CredReadW.restype = wintypes.BOOL
    advapi.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
    advapi.CredWriteW.restype = wintypes.BOOL
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    target = f"{SERVICE}:{account}"
    if value is not None:
        blob = value.encode("utf-16-le")
        buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        credential = CREDENTIAL()
        credential.Type = 1  # CRED_TYPE_GENERIC
        credential.TargetName = target
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = buffer
        credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = "mindspan-apps"
        if not advapi.CredWriteW(ctypes.byref(credential), 0):
            raise StoreError("Windows Credential Manager is unavailable or locked")
        return None
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not advapi.CredReadW(target, 1, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == 1168:  # ERROR_NOT_FOUND
            return None
        raise StoreError("Windows Credential Manager is unavailable or locked")
    try:
        blob = ctypes.string_at(pointer.contents.CredentialBlob,
                                pointer.contents.CredentialBlobSize)
        return blob.decode("utf-16-le")
    finally:
        advapi.CredFree(pointer)


def secure_store(client_id, value=None):
    account = store_account(client_id)
    system = platform.system()
    if system == "Darwin":
        return _mac_store(account, value)
    if system == "Windows":
        return _windows_store(account, value)
    if system == "Linux":
        return _linux_store(account, value)
    raise StoreError(f"No secure credential store is supported on {system}")


def client_id():
    value = os.environ.get("GOOGLE_CLIENT_ID", DEFAULT_GOOGLE_CLIENT_ID).strip()
    if not value:
        fail("CONFIG_REQUIRED", "GOOGLE_CLIENT_ID must name the Mindspan desktop OAuth client.",
             ask_user="Ask IT for the Mindspan apps client configuration.")
    return value


def client_secret():
    # Installed-app secrets are shared configuration, not per-user credentials.
    # Keep this value off the public CLI and fetch it from the WARP-only site.
    if configured := os.environ.get("GOOGLE_CLIENT_SECRET", "").strip():
        return configured
    request = urllib.request.Request(OAUTH_CONFIG_URL, headers={"Accept": "application/json"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(16_385)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        fail("API_UNAVAILABLE", "Could not load Mindspan sign-in configuration. Connect WARP and retry.",
             retryable=True)
    if len(raw) > 16_384:
        fail("API_UNAVAILABLE", "Mindspan sign-in configuration is invalid.", retryable=True)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        fail("API_UNAVAILABLE", "Mindspan sign-in configuration is invalid.", retryable=True)
    if (not isinstance(body, dict) or body.get("google_client_id") != client_id()
            or not isinstance(body.get("google_client_secret"), str)
            or not body["google_client_secret"]):
        fail("API_UNAVAILABLE", "Mindspan sign-in configuration is invalid.", retryable=True)
    return body["google_client_secret"]


def api_base():
    value = os.environ.get("MINDSPAN_APPS_API_URL", DEFAULT_API_URL).strip().rstrip("/")
    try:
        parsed = urllib.parse.urlparse(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        fail("CONFIG_REQUIRED", "MINDSPAN_APPS_API_URL is malformed.")
    safe_local = parsed.scheme == "http" and host in {"localhost", "127.0.0.1"}
    if not value or not (parsed.scheme == "https" or safe_local) or not parsed.netloc:
        fail("CONFIG_REQUIRED", "MINDSPAN_APPS_API_URL must be HTTPS (HTTP only for localhost).",
             ask_user="Ask IT for the Mindspan apps API address.")
    if (not host or parsed.username or parsed.password or parsed.path or parsed.query
            or parsed.fragment or (port is not None and not 1 <= port <= 65535)):
        fail("CONFIG_REQUIRED", "MINDSPAN_APPS_API_URL must contain only a scheme and host.")
    return value


def _json_request(url, *, method="GET", payload=None, headers=None, timeout=20):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Accept": "application/json", **(headers or {})})
    if data is not None:
        request.add_header("Content-Type", "application/json")
    status = None
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(2_000_001)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            exc.close()
            fail("API_UNAVAILABLE", "The apps API redirected a management request; refusing to forward your token.")
        status = exc.code
        raw = exc.read(2_000_001)
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        fail("API_UNAVAILABLE", "The apps API could not be reached.", retryable=True)
    if len(raw) > 2_000_000:
        fail("API_UNAVAILABLE", "The apps API response was too large.", retryable=True)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        fail("API_UNAVAILABLE", "The apps API did not return JSON.", retryable=True)
    if (not isinstance(body, dict) or not isinstance(body.get("ok"), bool)
            or not isinstance(body.get("code"), str)
            or not isinstance(body.get("message"), str)
            or not isinstance(body.get("retryable"), bool)
            or not isinstance(body.get("fix"), dict)
            or not isinstance(body.get("warnings"), list)):
        fail("API_UNAVAILABLE", "The apps API returned an invalid response.", retryable=True)
    if status is not None and status >= 400 and body["ok"]:
        fail("API_UNAVAILABLE", "The apps API returned an inconsistent HTTP status.", retryable=True)
    return body


def _token_request(fields):
    fields = {**fields, "client_secret": client_secret()}
    request = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(fields).encode(),
                                     method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            body = json.load(response)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            exc.close()
            fail("AUTH_REQUIRED", "Google's token endpoint redirected unexpectedly; sign-in was stopped.")
        if exc.code >= 500:
            fail("API_UNAVAILABLE", "Google sign-in is temporarily unavailable.", retryable=True)
        try:
            error = json.load(exc)
            detail = error.get("error_description") or error.get("error", "OAuth error")
        except (ValueError, AttributeError):
            detail = "OAuth error"
        fail("AUTH_REQUIRED", f"Google sign-in failed: {str(detail).rstrip('.')[:300]}.",
             command=tool_command(["login", "--json"]))
    except (urllib.error.URLError, TimeoutError, OSError):
        fail("API_UNAVAILABLE", "Google sign-in could not be reached.", retryable=True)
    if not isinstance(body, dict):
        fail("AUTH_REQUIRED", "Google returned an invalid token response.",
             command=tool_command(["login", "--json"]))
    return body


def _id_token():
    identity = client_id()
    try:
        refresh = secure_store(identity)
    except StoreError as exc:
        fail("AUTH_STORE_LOCKED", str(exc), ask_user="Unlock your OS credential store, then retry.")
    if not refresh:
        fail("AUTH_REQUIRED", "Sign in with your mindspan.org Google account.",
             command=tool_command(["login", "--json"]))
    result = _token_request({"client_id": identity, "refresh_token": refresh,
                             "grant_type": "refresh_token"})
    if result.get("refresh_token"):
        try:
            secure_store(identity, result["refresh_token"])
        except StoreError as exc:
            fail("AUTH_STORE_LOCKED", str(exc), ask_user="Unlock your OS credential store, then retry.")
    token = result.get("id_token")
    if not token:
        fail("AUTH_REQUIRED", "Google did not return an ID token; sign in again.",
             command=tool_command(["login", "--json"]))
    return token


def _github_oidc_token():
    """Ask the GitHub runner for a token scoped to this API's audience."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        fail("AUTH_REQUIRED", "GitHub OIDC deploys run only inside GitHub Actions.")
    address = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    runner_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    try:
        parsed = urllib.parse.urlparse(address)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        fail("AUTH_REQUIRED", "GitHub did not provide a trusted OIDC request endpoint.")
    if (parsed.scheme != "https" or not (host or "").endswith(".actions.githubusercontent.com")
            or port is not None
            or parsed.username or parsed.password or parsed.fragment or not runner_token):
        fail("AUTH_REQUIRED", "GitHub did not provide a trusted OIDC request endpoint.")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != "audience"]
    query.append(("audience", "mindspan-apps"))
    url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    request = urllib.request.Request(url, headers={
        "Authorization": "bearer " + runner_token, "Accept": "application/json"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            body = json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
        fail("AUTH_REQUIRED", "GitHub could not issue an OIDC token for this job.")
    token = body.get("value") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        fail("AUTH_REQUIRED", "GitHub returned no OIDC token for this job.")
    return token


def api_request(method, path, payload=None, *, query=None, timeout=20, identity="google"):
    base = api_base()
    url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    bearer = _github_oidc_token() if identity == "github" else _id_token()
    body = _json_request(url, method=method, payload=payload, timeout=timeout,
                         headers={"Authorization": "Bearer " + bearer})
    if identity == "google" and not body["ok"] and body["code"] == "AUTH_REQUIRED":
        body["fix"] = {"command": tool_command(["login", "--json"]), "ask_user": None}
    return body


def warp_state():
    exe = shutil.which("warp-cli")
    if not exe:
        return "unknown"
    try:
        status = subprocess.run([exe, "status"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if status.returncode:
        return "unknown"
    return "connected" if "Connected" in status.stdout else "off"


def doctor(args):
    identity = client_id()
    warning = []
    try:
        signed_in = bool(secure_store(identity)) if identity else False
        store_state = "available" if identity else "unconfigured"
    except StoreError:
        signed_in = False
        store_state = "unavailable"
        warning.append({"code": "AUTH_STORE_LOCKED", "message": "Unlock your OS credential store."})
    warp = warp_state()
    if warp == "off":
        warning.append({"code": "WARP_NOT_CONNECTED", "message": "Turn on WARP before opening an app."})
    emit(envelope(True, "OK", "Checked this machine.", warnings=warning,
                  os=platform.system(), python=platform.python_version(),
                  local_shell=True, warp=warp, signed_in=signed_in,
                  sign_in_unverified=signed_in, credential_store=store_state,
                  api_configured=bool(api_base()),
                  google_client_configured=bool(identity),
                  version=VERSION))


def _token_claims(token):
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return claims if isinstance(claims, dict) else {}
    except (IndexError, ValueError, UnicodeDecodeError, binascii.Error):
        return {}


def login(args):
    identity = client_id()
    # Verify the store exists before presenting an OAuth flow that cannot finish.
    try:
        secure_store(identity)
    except StoreError as exc:
        fail("AUTH_STORE_LOCKED", str(exc), ask_user="Unlock your OS credential store, then retry.")
    client_secret()  # Fail before opening Google if WARP sign-in configuration is unavailable.
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    result = {}

    class Callback(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            valid = parsed.path == "/callback" and hmac.compare_digest(params.get("state", [""])[0], state)
            if valid:
                result["code"] = params.get("code", [None])[0]
                result["error"] = params.get("error", [None])[0]
            self.send_response(200 if valid else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            message = "You can return to the Mindspan apps tool." if valid else "Invalid sign-in response."
            self.wfile.write(("<!doctype html><title>Mindspan apps</title><p>" + message + "</p>").encode())

        def log_message(self, format, *values):
            pass

    try:
        server = HTTPServer(("127.0.0.1", 0), Callback)
    except OSError:
        fail("API_UNAVAILABLE", "Could not start the local sign-in callback.", retryable=True)
    with server:
        redirect = f"http://127.0.0.1:{server.server_port}/callback"
        url = AUTH_URL + "?" + urllib.parse.urlencode({
            "client_id": identity, "redirect_uri": redirect, "response_type": "code",
            "scope": "openid email", "access_type": "offline", "prompt": "consent select_account",
            "hd": "mindspan.org", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        emit(envelope(True, "LOGIN_URL", "Open this link and choose your mindspan.org account.",
                      url=url), final=False)
        webbrowser.open(url)
        deadline = time.monotonic() + 300
        while not result and time.monotonic() < deadline:
            server.timeout = min(1, max(0.1, deadline - time.monotonic()))
            server.handle_request()
    if not result:
        fail("AUTH_REQUIRED", "Google sign-in timed out after five minutes.",
             command=tool_command(["login", "--json"]))
    if result.get("error") or not result.get("code"):
        fail("AUTH_REQUIRED", "Google sign-in was cancelled or declined.",
             command=tool_command(["login", "--json"]))
    tokens = _token_request({"client_id": identity, "code": result["code"],
                             "code_verifier": verifier, "redirect_uri": redirect,
                             "grant_type": "authorization_code"})
    claims = _token_claims(tokens.get("id_token", ""))
    if (claims.get("hd") != "mindspan.org" or claims.get("email_verified") not in (True, "true")
            or claims.get("aud") != identity or claims.get("nonce") != nonce
            or claims.get("iss") not in ("https://accounts.google.com", "accounts.google.com")):
        fail("AUTH_REQUIRED", "Google did not return a verified mindspan.org identity.",
             command=tool_command(["login", "--json"]))
    refresh = tokens.get("refresh_token")
    if not refresh:
        fail("AUTH_REQUIRED", "Google did not return a refresh token; retry sign-in.",
             command=tool_command(["login", "--json"]))
    try:
        secure_store(identity, refresh)
    except StoreError as exc:
        fail("AUTH_STORE_LOCKED", str(exc), ask_user="Unlock your OS credential store, then retry.")
    emit(envelope(True, "OK", "Signed in with Google.", email=claims.get("email")))


def name_path(name):
    return "/v1/apps/" + urllib.parse.quote(name, safe="")


class SourceError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _ignored(name):
    return name in {".git", "node_modules", ".venv"} or name.startswith(".env")


def buildpack_start_command(folder):
    """Require an explicit web process before spending a remote build."""
    if not ((folder / "package.json").is_file() or (folder / "requirements.txt").is_file()):
        return False
    procfile = folder / "Procfile"
    if procfile.is_file() and procfile.stat().st_size <= 16_384:
        try:
            if any(line.strip().startswith("web:") and line.split(":", 1)[1].strip()
                   for line in procfile.read_text(encoding="utf-8").splitlines()):
                return True
        except UnicodeError:
            return False
    package = folder / "package.json"
    if package.is_file() and package.stat().st_size <= 1_048_576:
        try:
            scripts = json.loads(package.read_text(encoding="utf-8")).get("scripts", {})
        except (ValueError, UnicodeError, AttributeError):
            return False
        return isinstance(scripts, dict) and isinstance(scripts.get("start"), str) and bool(scripts["start"].strip())
    return False


def package_source(folder):
    """Make a deterministic tar.gz containing only safe regular source files.

    The caller owns the returned temporary archive and must remove it in a
    finally block. No source path is included merely because it exists: links,
    special files, oversized files, and unsafe names fail closed.
    """
    source = Path(folder)
    if source.is_symlink() or not source.is_dir():
        raise SourceError("NO_ENTRYPOINT", "Deploy path must be a real directory.")
    root = source.resolve(strict=True)
    entries = []
    expanded = 0
    def walk_error(error):
        raise SourceError("UNSAFE_SOURCE", "Source folder could not be read safely.") from error

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False,
                                        onerror=walk_error):
        dirs[:] = sorted(name for name in dirs if not _ignored(name))
        for name in dirs:
            path = Path(current) / name
            if path.is_symlink():
                raise SourceError("UNSAFE_SOURCE", f"Source contains a linked directory: {path.relative_to(root)}")
        for name in sorted(files):
            if _ignored(name):
                continue
            path = Path(current) / name
            relative = path.relative_to(root)
            if (any(part in {"", ".", ".."} or "\\" in part for part in relative.parts)
                    or len(relative.as_posix().encode("utf-8")) > 512):
                raise SourceError("UNSAFE_SOURCE", "Source contains an unsafe path name.")
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SourceError("UNSAFE_SOURCE", f"Source contains a link or special file: {relative}")
            if not path.resolve(strict=True).is_relative_to(root):
                raise SourceError("UNSAFE_SOURCE", f"Source path escapes its folder: {relative}")
            if info.st_size > MAX_FILE:
                raise SourceError("TOO_LARGE", f"Source file exceeds the per-file limit: {relative}")
            expanded += info.st_size
            if expanded > MAX_EXPANDED or len(entries) >= MAX_FILES:
                raise SourceError("TOO_LARGE", "Source exceeds the file-count or expanded-size limit.")
            entries.append((path, relative.as_posix(), info))
    names = {name for _, name, _ in entries}
    if not names:
        raise SourceError("NO_ENTRYPOINT", "The source folder has no deployable files.")
    if "Dockerfile" in names:
        detected = "dockerfile"
    elif "package.json" in names or "requirements.txt" in names:
        detected = "buildpack"
    elif "index.html" in names:
        detected = "static"
    else:
        raise SourceError("NO_ENTRYPOINT", "Add an index.html, Dockerfile, or app manifest.")

    temp = tempfile.NamedTemporaryFile(prefix="mindspan-apps-", suffix=".tar.gz", delete=False)
    archive_path = Path(temp.name)
    try:
        with temp:
            with gzip.GzipFile(filename="", mode="wb", fileobj=temp, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                    for path, name, original in entries:
                        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                        try:
                            fd = os.open(path, flags)
                        except OSError as exc:
                            raise SourceError("UNSAFE_SOURCE", f"Source changed while packaging: {name}") from exc
                        with os.fdopen(fd, "rb") as stream:
                            current = os.fstat(stream.fileno())
                            if (not stat.S_ISREG(current.st_mode)
                                    or (current.st_dev, current.st_ino, current.st_size) !=
                                    (original.st_dev, original.st_ino, original.st_size)):
                                raise SourceError("UNSAFE_SOURCE", f"Source changed while packaging: {name}")
                            item = tarfile.TarInfo(name)
                            item.size = current.st_size
                            item.mode = 0o644
                            item.mtime = 0
                            tar.addfile(item, stream)
                            after = os.fstat(stream.fileno())
                            if (after.st_size, after.st_mtime_ns) != (original.st_size, original.st_mtime_ns):
                                raise SourceError("UNSAFE_SOURCE", f"Source changed while packaging: {name}")
        size = archive_path.stat().st_size
        if size > MAX_ARCHIVE:
            raise SourceError("TOO_LARGE", "Compressed upload exceeds 200 MB.")
        digest = hashlib.sha256()
        with archive_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return {"path": archive_path, "bytes": size, "sha256": digest.hexdigest(),
                "files": len(entries), "detected": detected, "has_index": "index.html" in names}
    except BaseException:
        archive_path.unlink(missing_ok=True)
        raise


def upload_signed(upload, archive):
    """Stream an archive to the single-use signed GCS URL, without a bearer token."""
    if not isinstance(upload, dict) or upload.get("method") != "PUT":
        raise SourceError("API_UNAVAILABLE", "The API did not provide a PUT upload.")
    try:
        url = urllib.parse.urlparse(upload.get("url", ""))
        host, port = url.hostname, url.port
    except (TypeError, ValueError) as exc:
        raise SourceError("API_UNAVAILABLE", "The API returned an invalid upload address.") from exc
    api_address = os.environ.get("MINDSPAN_APPS_API_URL", "")
    control = None
    try:
        control = urllib.parse.urlparse(api_address)
        control_host = control.hostname
    except ValueError:
        control_host = None
    local = (url.scheme == "http" and host in {"127.0.0.1", "localhost"}
             and control is not None and control.scheme == "http"
             and control_host in {"127.0.0.1", "localhost"})
    google = url.scheme == "https" and (
        host == "storage.googleapis.com" or
        (host or "").endswith(".storage.googleapis.com"))
    if (not (google or local) or url.username or url.password or url.fragment
            or not host or port == 0):
        raise SourceError("API_UNAVAILABLE", "The API returned an unsafe upload address.")
    headers = upload.get("headers")
    if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                 for k, v in headers.items()):
        raise SourceError("API_UNAVAILABLE", "The API returned invalid upload headers.")
    expected = {"content-type": "application/gzip",
                "x-goog-if-generation-match": "0",
                "x-goog-content-length-range": f"{archive['bytes']},{archive['bytes']}",
                "x-goog-meta-sha256": archive["sha256"]}
    normalized = {key.lower(): value for key, value in headers.items()}
    if (len(normalized) != len(headers) or normalized != expected
            or any("\r" in part or "\n" in part for pair in headers.items() for part in pair)):
        raise SourceError("API_UNAVAILABLE", "The signed upload does not match the archive.")
    connection_type = http.client.HTTPConnection if local else http.client.HTTPSConnection
    try:
        connection = connection_type(host, port=port, timeout=60)
    except (OSError, ValueError) as exc:
        raise SourceError("API_UNAVAILABLE", "The API returned an invalid upload address.") from exc
    try:
        target = url.path or "/"
        if url.query:
            target += "?" + url.query
        connection.putrequest("PUT", target, skip_accept_encoding=True)
        for key, value in headers.items():
            connection.putheader(key, value)
        connection.putheader("Content-Length", str(archive["bytes"]))
        connection.endheaders()
        with archive["path"].open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                connection.send(chunk)
        response = connection.getresponse()
        response.read(8192)
        if response.status not in {200, 201, 204}:
            raise SourceError("UPLOAD_FAILED", f"Signed upload failed with HTTP {response.status}.")
    except (OSError, http.client.HTTPException) as exc:
        raise SourceError("UPLOAD_FAILED", "Signed upload could not be completed.") from exc
    finally:
        connection.close()


PENDING_STATES = {"awaiting_upload", "upload_verified", "building", "deploying", "finalizing"}
TERMINAL_STATES = {"succeeded", "failed", "superseded"}


def deployment_result(body):
    """Turn a status envelope into a truthful final or pending client result."""
    if not body["ok"]:
        return body
    deploy = body.get("deploy")
    if not isinstance(deploy, dict) or not isinstance(deploy.get("id"), str):
        return envelope(False, "API_UNAVAILABLE", "The API returned no deploy ID.", retryable=True)
    state = deploy.get("state")
    if state == "succeeded":
        if not isinstance(deploy.get("url"), str):
            return envelope(False, "API_UNAVAILABLE", "The API reported success without an app URL.")
        return envelope(True, "DEPLOYED", "The app is active.", deploy=deploy, url=deploy["url"])
    if state == "failed":
        return envelope(False, deploy.get("failure_code") or "DEPLOY_FAILED",
                        deploy.get("failure_message") or "The deployment failed.", deploy=deploy)
    if state == "superseded":
        return envelope(False, "DEPLOY_SUPERSEDED", "A newer deployment replaced this attempt.", deploy=deploy)
    if state in PENDING_STATES:
        return envelope(True, "DEPLOY_PENDING", "Deployment is not active yet.",
                        deploy=deploy, deploy_id=deploy["id"],
                        fix={"command": tool_command(["deploys", "wait", deploy["id"], "--json"]),
                             "ask_user": None})
    return envelope(False, "API_UNAVAILABLE", "The API returned an unknown deployment state.", retryable=True)


def wait_once(deploy_id, *, identity="google"):
    body = api_request("GET", "/v1/deploys/" + urllib.parse.quote(deploy_id, safe=""),
                       query={"wait_seconds": 60}, timeout=70, identity=identity)
    return deployment_result(body)


def deploy_request_id(name, archive, identity):
    if identity == "github":
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        if not repository.startswith("mindspanorg/") or not run_id.isdecimal():
            fail("CONFIG_REQUIRED", "GitHub did not provide a stable workflow run ID.")
        # A rerun of the same GitHub job resumes its deployment instead of
        # allocating another generation after an upload/network interruption.
        seed = f"mindspan-apps:{repository}:{run_id}:{name}:{archive['sha256']}"
        return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
    return str(uuid.uuid4())


def deploys_wait(args):
    emit(wait_once(args.id))


def deploy(args):
    if not args.accept_data_rule:
        fail("DATA_RULE_REQUIRED", "Apps may not hold personal, research, financial, or regulated data.",
             ask_user="Does this app follow the no-sensitive-data rule? Retry with --accept-data-rule if yes.")
    name = args.name or Path(args.path).name
    if not name:
        fail("NAME_INVALID", "Provide an app name with --name.")
    archive = None
    identity = getattr(args, "identity", "google")
    try:
        archive = package_source(args.path)
        app_type = args.type or archive["detected"]
        if app_type == "static" and not archive["has_index"]:
            fail("NO_ENTRYPOINT", "Static deployment needs a root index.html.")
        if app_type == "dockerfile" and not (Path(args.path) / "Dockerfile").is_file():
            fail("NO_ENTRYPOINT", "Dockerfile deployment needs a root Dockerfile.")
        if app_type == "buildpack" and not buildpack_start_command(Path(args.path)):
            fail("NO_START_COMMAND", "Add package.json scripts.start or a root Procfile web: command; build frontend-only projects first and deploy their output folder.")
        init = api_request("POST", name_path(name) + "/deploys", {
            "request_id": deploy_request_id(name, archive, identity),
            "archive_sha256": archive["sha256"],
            "archive_size": archive["bytes"], "type": app_type,
            "accept_data_rule": True,
        }, identity=identity)
        if not init["ok"]:
            emit(init)
        initial_result = deployment_result(init)
        if not initial_result["ok"]:
            emit(initial_result)
        if initial_result["code"] == "DEPLOYED":
            emit(initial_result)
        deploy_id = initial_result["deploy_id"]
        if initial_result["deploy"]["state"] == "awaiting_upload":
            upload_signed(init.get("upload"), archive)
            completed = api_request("POST", "/v1/deploys/" + urllib.parse.quote(deploy_id, safe="") +
                                    "/complete", identity=identity)
            if not completed["ok"]:
                emit(completed)
            initial_result = deployment_result(completed)
            if not initial_result["ok"]:
                emit(initial_result)
        if args.no_wait or initial_result["code"] == "DEPLOYED":
            emit(initial_result)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            current = wait_once(deploy_id, identity=identity)
            if current["code"] != "DEPLOY_PENDING":
                emit(current)
            emit(current, final=False)
        emit(envelope(False, "DEPLOY_PENDING", "Deployment is still running; success is not confirmed.",
                      retryable=True,
                      deploy_id=deploy_id,
                      fix={"command": tool_command(["deploys", "wait", deploy_id, "--json"]),
                           "ask_user": None}))
    except SourceError as exc:
        fail(exc.code, str(exc))
    except OSError:
        fail("UNSAFE_SOURCE", "Could not read or package the source folder.")
    finally:
        if archive is not None:
            archive["path"].unlink(missing_ok=True)


def github_deploy(args):
    """Deploy from the approved reusable workflow after pin/link bootstrap."""
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or not repository.startswith("mindspanorg/")
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"}):
        fail("AUTH_REQUIRED", "GitHub deploy needs a mindspanorg main-branch push or dispatch.")
    checkout = os.environ.get("MINDSPAN_APPS_SOURCE_ROOT", "")
    if not checkout:
        fail("CONFIG_REQUIRED", "The workflow did not set MINDSPAN_APPS_SOURCE_ROOT.")
    root = Path(checkout).resolve()
    source = Path(args.path).resolve()
    if not root.is_dir() or not source.is_relative_to(root):
        fail("UNSAFE_SOURCE", "The deploy source must stay inside the caller repository checkout.")
    pin = api_request("POST", name_path(args.name) + "/link/pin", {},
                      identity="github")
    if not pin["ok"]:
        emit(pin)
    args.identity = "github"
    deploy(args)


def reserve(args):
    if not args.accept_data_rule:
        fail("DATA_RULE_REQUIRED", "Apps may not hold personal, research, financial, or regulated data.",
             ask_user="Does this app follow the no-sensitive-data rule? Retry with --accept-data-rule if yes.")
    emit(api_request("POST", name_path(args.name) + "/reserve",
                     {"description": args.description or "", "accept_data_rule": True}))


def release(args):
    emit(api_request("POST", name_path(args.name) + "/release"))


def list_apps(args):
    emit(api_request("GET", "/v1/apps", query={"mine": str(args.mine).lower()}))


def status(args):
    emit(api_request("GET", name_path(args.name)))


def renew(args):
    emit(api_request("POST", name_path(args.name) + "/renew"))


def admin_freeze(args):
    emit(api_request("POST", "/v1/admin/apps/" + urllib.parse.quote(args.name, safe="") +
                     ("/freeze" if args.admin_command == "freeze" else "/unfreeze")))


def link(args):
    staged = api_request("POST", name_path(args.name) + "/link/stage",
                         {"repository": args.repo})
    if not staged["ok"]:
        emit(staged)
    pending = staged.get("pending_repository")
    if not isinstance(pending, dict):
        fail("API_UNAVAILABLE", "The API did not return the pending repository link.")
    if pending.get("repository_id") is None:
        staged["fix"] = {"command": None, "ask_user":
                         "Run the linked repository's reusable deploy workflow once to pin its ID, then rerun link."}
        emit(staged)
    emit(api_request("POST", name_path(args.name) + "/confirmations", {"action": "link"}))


def confirmation_action(args):
    if args.command == "delete":
        name = args.name
        payload = {"action": "delete"}
    else:
        name = args.app
        payload = {"action": "owners_" + args.owner_command, "email": args.email}
    emit(api_request("POST", name_path(name) + "/confirmations", payload))


def confirmation_wait(args):
    deadline = time.monotonic() + 50
    path = "/v1/confirmations/" + urllib.parse.quote(args.id, safe="")
    while True:
        body = api_request("GET", path)
        if not body["ok"]:
            emit(body)
        confirmation = body.get("confirmation")
        if not isinstance(confirmation, dict):
            fail("API_UNAVAILABLE", "The API returned no confirmation state.")
        state = confirmation.get("state")
        if state == "completed":
            # A completed browser flow is not itself proof that the requested
            # mutation succeeded; preserve the server's recorded outcome.
            emit(envelope(True, "CONFIRMATION_COMPLETED", "Browser confirmation completed.",
                          confirmation=confirmation))
        if state == "expired":
            emit(envelope(False, "CONFIRMATION_EXPIRED", "Browser confirmation expired.",
                          confirmation=confirmation))
        if state not in {"pending", "applying"}:
            fail("API_UNAVAILABLE", "The API returned an unknown confirmation state.")
        if time.monotonic() >= deadline:
            emit(envelope(True, "CONFIRMATION_PENDING", "Waiting for browser confirmation.",
                          confirmation=confirmation,
                          fix={"command": tool_command(["confirmations", "wait", args.id, "--json"]),
                               "ask_user": None}))
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def not_implemented(args):
    fail("NOT_IMPLEMENTED", f"{args.command} is not implemented in this engineering slice.")


class JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        fail("USAGE_ERROR", message)


def main(argv=None):
    parser = JSONArgumentParser(prog="mindspan-apps")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=JSONArgumentParser)
    sub.add_parser("doctor").set_defaults(run=doctor)
    sub.add_parser("login").set_defaults(run=login)
    p = sub.add_parser("reserve")
    p.add_argument("name")
    p.add_argument("--description", default="")
    p.add_argument("--accept-data-rule", action="store_true")
    p.set_defaults(run=reserve)
    p = sub.add_parser("release")
    p.add_argument("name")
    p.set_defaults(run=release)
    p = sub.add_parser("list")
    p.add_argument("--mine", action="store_true")
    p.set_defaults(run=list_apps)
    p = sub.add_parser("status")
    p.add_argument("name")
    p.set_defaults(run=status)
    p = sub.add_parser("renew")
    p.add_argument("name")
    p.set_defaults(run=renew)
    p = sub.add_parser("deploy")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--name")
    p.add_argument("--no-wait", action="store_true")
    p.add_argument("--type", choices=["dockerfile", "buildpack", "static"])
    p.add_argument("--accept-data-rule", action="store_true")
    p.set_defaults(run=deploy)
    p = sub.add_parser("github-deploy")
    p.add_argument("path")
    p.add_argument("--name", required=True)
    p.add_argument("--accept-data-rule", action="store_true")
    p.add_argument("--no-wait", action="store_true")
    p.add_argument("--type", choices=["dockerfile", "buildpack", "static"])
    p.set_defaults(run=github_deploy)
    p = sub.add_parser("deploys")
    deploy_sub = p.add_subparsers(dest="deploy_command", required=True)
    wait = deploy_sub.add_parser("wait")
    wait.add_argument("id")
    wait.set_defaults(run=deploys_wait)
    for name in ("logs", "rollback"):
        p = sub.add_parser(name)
        p.add_argument("name")
        p.set_defaults(run=not_implemented)
    p = sub.add_parser("delete")
    p.add_argument("name")
    p.set_defaults(run=confirmation_action)
    p = sub.add_parser("link")
    p.add_argument("name")
    p.add_argument("repo")
    p.set_defaults(run=link)
    p = sub.add_parser("owners")
    owner_sub = p.add_subparsers(dest="owner_command", required=True)
    for name in ("add", "remove"):
        action = owner_sub.add_parser(name)
        action.add_argument("app")
        action.add_argument("email")
        action.set_defaults(run=confirmation_action)
    p = sub.add_parser("confirmations")
    confirmation_sub = p.add_subparsers(dest="confirmation_command", required=True)
    wait = confirmation_sub.add_parser("wait")
    wait.add_argument("id")
    wait.set_defaults(run=confirmation_wait)
    p = sub.add_parser("admin")
    admin_sub = p.add_subparsers(dest="admin_command", required=True)
    expiring = admin_sub.add_parser("expiring")
    expiring.add_argument("--days", type=int, default=60)
    expiring.set_defaults(run=not_implemented)
    for name in ("freeze", "unfreeze"):
        action = admin_sub.add_parser(name)
        action.add_argument("name")
        action.set_defaults(run=admin_freeze)
    args = parser.parse_args([item for item in (argv if argv is not None else sys.argv[1:])
                              if item != "--json"])
    args.run(args)


if __name__ == "__main__":
    main()
