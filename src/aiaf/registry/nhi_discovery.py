"""Automated NHI Discovery — scan the local environment for non-human identities.

Discovers machine identities from five sources:
  ENV_VAR      — environment variables matching credential/token/key patterns
  FILESYSTEM   — well-known credential file paths (SSH keys, TLS certs, cloud creds)
  KUBERNETES   — Kubernetes service account token mounts
  CLOUD_IAM    — cloud-provider credential files at known absolute paths
  PROC_ENV     — other process environments via /proc/*/environ (Linux, root-only)

Discovered identities are returned as NHICandidate dicts, each compatible with
nhi_registry.register_nhi().  Actual credential values are NEVER included in
candidates — only metadata (var names, file paths, inferred types, confidence).

Evidence origin: LOCALLY_OBSERVED.
SECURITY NOTE: This module is strictly read-only; it transmits no data externally.
"""

from __future__ import annotations

import glob
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NHI_DISCOVERY_VERSION = "1.0"

# ── Discovery source types ─────────────────────────────────────────────────────
SOURCE_ENV_VAR = "ENV_VAR"
SOURCE_FILESYSTEM = "FILESYSTEM"
SOURCE_KUBERNETES = "KUBERNETES"
SOURCE_CLOUD_IAM = "CLOUD_IAM"
SOURCE_PROC_ENV = "PROC_ENV"

DISCOVERY_SOURCES: frozenset = frozenset({
    SOURCE_ENV_VAR, SOURCE_FILESYSTEM, SOURCE_KUBERNETES,
    SOURCE_CLOUD_IAM, SOURCE_PROC_ENV,
})

# ── Confidence levels ──────────────────────────────────────────────────────────
CONFIDENCE_HIGH = "HIGH"       # Private key, SA token, named cloud credential
CONFIDENCE_MEDIUM = "MEDIUM"   # Generic API key pattern, kubeconfig
CONFIDENCE_LOW = "LOW"         # Generic SECRET/PASSWORD/CREDENTIAL variable

_CONFIDENCE_RANK: dict[str, int] = {
    CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2,
}

# ── NHI types (from nhi_registry) ─────────────────────────────────────────────
_NHI_AGENT_WORKER = "AGENT_WORKER"
_NHI_PIPELINE_RUNNER = "PIPELINE_RUNNER"
_NHI_DATA_CONNECTOR = "DATA_CONNECTOR"
_NHI_GATEWAY = "GATEWAY"

# ── Environment variable credential patterns ───────────────────────────────────
# Each tuple: (compiled_regex, inferred_nhi_type, confidence)
_ENV_PATTERNS: list[tuple] = [
    # Named AI-provider tokens (highest specificity first)
    (re.compile(r"\bANTHROPIC_API_KEY\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    (re.compile(r"\bOPENAI_API_KEY\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    (re.compile(r"\bHF_TOKEN\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    (re.compile(r"\bHUGGINGFACE_TOKEN\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    (re.compile(r"\bCOHERE_API_KEY\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    (re.compile(r"\bMISTRAL_API_KEY\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    # Cloud credentials (named)
    (re.compile(r"\bAWS_ACCESS_KEY_ID\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH),
    (re.compile(r"\bAWS_SECRET_ACCESS_KEY\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH),
    (re.compile(r"\bAWS_SESSION_TOKEN\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH),
    (re.compile(r"\bGOOGLE_APPLICATION_CREDENTIALS\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH),
    (re.compile(r"\bGCLOUD_SERVICE_ACCOUNT\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH),
    (re.compile(r"\bAZURE_CLIENT_SECRET\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH),
    (re.compile(r"\bAZURE_CLIENT_ID\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_MEDIUM),
    # Kubernetes
    (re.compile(r"\bKUBECONFIG\b", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_MEDIUM),
    (re.compile(r"\bSERVICE_ACCOUNT_TOKEN\b", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    # Generic suffix patterns (lower specificity)
    (re.compile(r"_PRIVATE_KEY$", re.I), _NHI_AGENT_WORKER, CONFIDENCE_HIGH),
    (re.compile(r"_API_KEY$", re.I), _NHI_AGENT_WORKER, CONFIDENCE_MEDIUM),
    (re.compile(r"_TOKEN$", re.I), _NHI_AGENT_WORKER, CONFIDENCE_MEDIUM),
    (re.compile(r"_ACCESS_KEY$", re.I), _NHI_PIPELINE_RUNNER, CONFIDENCE_MEDIUM),
    (re.compile(r"_SECRET$", re.I), _NHI_AGENT_WORKER, CONFIDENCE_LOW),
    (re.compile(r"_PASSWORD$", re.I), _NHI_DATA_CONNECTOR, CONFIDENCE_LOW),
    (re.compile(r"_CREDENTIALS?$", re.I), _NHI_AGENT_WORKER, CONFIDENCE_LOW),
]

# ── Well-known filesystem paths (relative to home or root) ────────────────────
# Each tuple: (path_pattern, nhi_type, confidence, description, is_root_relative)
_FS_PATHS: list[tuple] = [
    # SSH private keys
    (".ssh/id_rsa", _NHI_DATA_CONNECTOR, CONFIDENCE_HIGH, "SSH RSA private key", False),
    (".ssh/id_ed25519", _NHI_DATA_CONNECTOR, CONFIDENCE_HIGH, "SSH Ed25519 private key", False),
    (".ssh/id_ecdsa", _NHI_DATA_CONNECTOR, CONFIDENCE_HIGH, "SSH ECDSA private key", False),
    (".ssh/id_dsa", _NHI_DATA_CONNECTOR, CONFIDENCE_HIGH, "SSH DSA private key (deprecated)", False),
    # TLS private keys
    ("etc/ssl/private/*.key", _NHI_GATEWAY, CONFIDENCE_HIGH, "TLS private key (ssl/private)", True),
    ("etc/pki/tls/private/*.key", _NHI_GATEWAY, CONFIDENCE_HIGH, "TLS private key (pki/tls)", True),
    # AWS
    (".aws/credentials", _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH, "AWS credentials file", False),
    # GCP
    (".config/gcloud/application_default_credentials.json",
     _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH, "GCP application default credentials", False),
    # Azure
    (".azure/accessTokens.json", _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH, "Azure CLI access tokens", False),
    (".azure/msal_token_cache.json", _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH, "Azure MSAL token cache", False),
    # Kubernetes
    (".kube/config", _NHI_PIPELINE_RUNNER, CONFIDENCE_HIGH, "Kubernetes kubeconfig", False),
    # Docker
    (".docker/config.json", _NHI_AGENT_WORKER, CONFIDENCE_MEDIUM, "Docker registry credentials", False),
    # GitHub CLI
    (".config/gh/hosts.yml", _NHI_PIPELINE_RUNNER, CONFIDENCE_MEDIUM, "GitHub CLI hosts config", False),
    # Service account key files
    ("*.service-account.json", _NHI_AGENT_WORKER, CONFIDENCE_HIGH, "Service account key file", False),
]

# ── Kubernetes service account well-known paths ───────────────────────────────
_K8S_SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_K8S_SA_NAMESPACE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
_K8S_SA_CACERT = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# ── Cloud credential absolute paths ──────────────────────────────────────────
_CLOUD_ABSOLUTE_PATHS: list[dict[str, str]] = [
    {
        "path": "/run/secrets/kubernetes.io/serviceaccount/token",
        "provider": "kubernetes",
        "nhi_type": _NHI_AGENT_WORKER,
        "confidence": CONFIDENCE_HIGH,
        "description": "Kubernetes SA token (alternative /run mount)",
    },
    {
        "path": "/var/run/secrets/tokens/bound-token",
        "provider": "kubernetes",
        "nhi_type": _NHI_AGENT_WORKER,
        "confidence": CONFIDENCE_HIGH,
        "description": "Kubernetes projected service account token",
    },
    {
        "path": "/run/secrets/workload-identity",
        "provider": "cloud_iam",
        "nhi_type": _NHI_PIPELINE_RUNNER,
        "confidence": CONFIDENCE_HIGH,
        "description": "Cloud workload identity credential",
    },
    {
        "path": "/run/secrets/egress-token",
        "provider": "kubernetes",
        "nhi_type": _NHI_GATEWAY,
        "confidence": CONFIDENCE_MEDIUM,
        "description": "Kubernetes projected egress token",
    },
]


class NHIDiscoveryError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _make_candidate(
    nhi_id: str,
    nhi_type: str,
    source: str,
    confidence: str,
    *,
    description: str = "",
    environment: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "nhi_id": nhi_id,
        "nhi_type": nhi_type,
        "source": source,
        "confidence": confidence,
        "description": description,
        "environment": environment,
        "attributes": attributes or {},
        "discovered_at": _utc_now(),
        "evidence_origin": "LOCALLY_OBSERVED",
        "nhi_discovery_version": NHI_DISCOVERY_VERSION,
    }


# ── Public scanners ────────────────────────────────────────────────────────────

def scan_environment_variables(
    env: dict[str, str] | None = None,
    *,
    min_confidence: str = CONFIDENCE_LOW,
) -> list[dict[str, Any]]:
    """Scan environment variables for credential patterns.

    Parameters
    ----------
    env:            Environment dict to scan.  Defaults to ``os.environ``.
    min_confidence: Minimum confidence level to include (HIGH, MEDIUM, LOW).

    Returns
    -------
    List of NHICandidate dicts.  Actual credential values are never included.
    """
    env = env if env is not None else dict(os.environ)
    min_rank = _CONFIDENCE_RANK.get(min_confidence, 0)

    seen: set = set()
    candidates: list[dict[str, Any]] = []

    for var_name, value in env.items():
        if not value:
            continue
        for pattern, nhi_type, confidence in _ENV_PATTERNS:
            if _CONFIDENCE_RANK.get(confidence, 0) < min_rank:
                continue
            if pattern.search(var_name):
                key = (var_name, nhi_type)
                if key in seen:
                    break
                seen.add(key)
                candidates.append(_make_candidate(
                    nhi_id=f"env:{var_name.lower()}",
                    nhi_type=nhi_type,
                    source=SOURCE_ENV_VAR,
                    confidence=confidence,
                    description=f"Env var {var_name!r} matches credential pattern.",
                    attributes={"env_var": var_name},
                ))
                break

    return candidates


def scan_filesystem_paths(
    home: str | None = None,
    *,
    root: str = "/",
    min_confidence: str = CONFIDENCE_LOW,
    path_exists_fn=None,
    glob_fn=None,
) -> list[dict[str, Any]]:
    """Scan well-known filesystem paths for credential files.

    Parameters
    ----------
    home:           Home directory.  Defaults to ``os.path.expanduser("~")``.
    root:           Filesystem root for absolute paths.  Defaults to ``"/"``.
    min_confidence: Minimum confidence to include.
    path_exists_fn: Override for os.path.isfile (injectable for testing).
    glob_fn:        Override for glob.glob (injectable for testing).

    Returns
    -------
    List of NHICandidate dicts.
    """
    if home is None:
        home = os.path.expanduser("~")

    min_rank = _CONFIDENCE_RANK.get(min_confidence, 0)
    exists = path_exists_fn or os.path.isfile
    do_glob = glob_fn or glob.glob

    candidates: list[dict[str, Any]] = []
    seen: set = set()

    for path_pat, nhi_type, confidence, description, is_root_relative in _FS_PATHS:
        if _CONFIDENCE_RANK.get(confidence, 0) < min_rank:
            continue

        base = root if is_root_relative else home
        full_pattern = os.path.join(base, path_pat)

        matched_paths: list[str]
        if "*" in path_pat:
            matched_paths = do_glob(full_pattern)
        else:
            matched_paths = [full_pattern] if exists(full_pattern) else []

        for matched in matched_paths:
            if not exists(matched):
                continue
            if matched in seen:
                continue
            seen.add(matched)
            display_id = matched.replace(home, "~").replace(root.rstrip("/"), "")
            candidates.append(_make_candidate(
                nhi_id=f"file:{display_id}",
                nhi_type=nhi_type,
                source=SOURCE_FILESYSTEM,
                confidence=confidence,
                description=description,
                attributes={"file_path": matched},
            ))

    return candidates


def scan_kubernetes_service_accounts(
    *,
    sa_token_path: str = _K8S_SA_TOKEN,
    path_exists_fn=None,
    read_text_fn=None,
) -> list[dict[str, Any]]:
    """Detect Kubernetes service account tokens at well-known mount paths.

    Returns empty list when not running inside a Kubernetes pod.

    Parameters
    ----------
    sa_token_path:  Path to the service account token file.
    path_exists_fn: Override for os.path.isfile (injectable for testing).
    read_text_fn:   Override for Path.read_text (injectable for testing).
    """
    exists = path_exists_fn or os.path.isfile

    if not exists(sa_token_path):
        return []

    namespace: str | None = None
    ns_path = os.path.join(os.path.dirname(sa_token_path), "namespace")
    if exists(ns_path):
        if read_text_fn:
            try:
                namespace = read_text_fn(ns_path).strip()
            except Exception:
                pass
        else:
            try:
                namespace = Path(ns_path).read_text().strip()
            except Exception:
                pass

    return [_make_candidate(
        nhi_id="k8s:serviceaccount:default",
        nhi_type=_NHI_AGENT_WORKER,
        source=SOURCE_KUBERNETES,
        confidence=CONFIDENCE_HIGH,
        description="Kubernetes service account token at standard mount path.",
        environment=f"kubernetes:{namespace}" if namespace else "kubernetes",
        attributes={
            "token_path": sa_token_path,
            "namespace": namespace,
            "has_cacert": exists(_K8S_SA_CACERT),
        },
    )]


def scan_cloud_credentials(
    *,
    path_exists_fn=None,
) -> list[dict[str, Any]]:
    """Detect cloud provider credential files at well-known absolute paths.

    Parameters
    ----------
    path_exists_fn: Override for os.path.isfile (injectable for testing).

    Returns
    -------
    List of NHICandidate dicts for each detected cloud credential file.
    """
    exists = path_exists_fn or os.path.isfile
    candidates: list[dict[str, Any]] = []

    for spec in _CLOUD_ABSOLUTE_PATHS:
        if exists(spec["path"]):
            candidates.append(_make_candidate(
                nhi_id=f"cloud:{spec['provider']}:{os.path.basename(spec['path'])}",
                nhi_type=spec["nhi_type"],
                source=SOURCE_CLOUD_IAM,
                confidence=spec["confidence"],
                description=spec["description"],
                environment=spec["provider"],
                attributes={"credential_path": spec["path"], "provider": spec["provider"]},
            ))

    return candidates


def scan_proc_environments(
    *,
    proc_root: str = "/proc",
    skip_self: bool = True,
    min_confidence: str = CONFIDENCE_MEDIUM,
) -> list[dict[str, Any]]:
    """Scan other processes' environments via /proc/*/environ (Linux, root-only).

    Returns empty list on non-Linux systems or when /proc is not accessible.

    Parameters
    ----------
    proc_root:      /proc filesystem path (injectable for testing).
    skip_self:      Skip the current process's own PID.
    min_confidence: Minimum confidence to include.
    """
    proc_path = Path(proc_root)
    if not proc_path.is_dir():
        return []

    min_rank = _CONFIDENCE_RANK.get(min_confidence, 0)
    self_pid = str(os.getpid())
    candidates: list[dict[str, Any]] = []
    seen: set = set()

    for pid_dir in sorted(proc_path.iterdir()):
        if not pid_dir.name.isdigit():
            continue
        if skip_self and pid_dir.name == self_pid:
            continue

        environ_file = pid_dir / "environ"
        try:
            raw = environ_file.read_bytes()
        except (PermissionError, ProcessLookupError, FileNotFoundError, OSError):
            continue

        # /proc/<pid>/environ: NUL-separated key=value pairs
        env_pairs: dict[str, str] = {}
        for part in raw.split(b"\x00"):
            if b"=" in part:
                k, _, v = part.partition(b"=")
                try:
                    env_pairs[k.decode("utf-8", errors="replace")] = v.decode("utf-8", errors="replace")
                except Exception:
                    pass

        for var_name, value in env_pairs.items():
            if not value:
                continue
            for pattern, nhi_type, confidence in _ENV_PATTERNS:
                if _CONFIDENCE_RANK.get(confidence, 0) < min_rank:
                    continue
                if pattern.search(var_name):
                    key = (pid_dir.name, var_name)
                    if key in seen:
                        break
                    seen.add(key)
                    candidates.append(_make_candidate(
                        nhi_id=f"proc:{pid_dir.name}:env:{var_name.lower()}",
                        nhi_type=nhi_type,
                        source=SOURCE_PROC_ENV,
                        confidence=confidence,
                        description=f"Credential var {var_name!r} in PID {pid_dir.name} environment.",
                        attributes={"pid": pid_dir.name, "env_var": var_name},
                    ))
                    break

    return candidates


def discover_nhis(
    *,
    env: dict[str, str] | None = None,
    home: str | None = None,
    filesystem_root: str = "/",
    scan_proc: bool = False,
    min_confidence: str = CONFIDENCE_LOW,
    sources: list[str] | None = None,
    path_exists_fn=None,
    glob_fn=None,
) -> dict[str, Any]:
    """Run all NHI discovery scanners and return a consolidated report.

    Parameters
    ----------
    env:             Environment dict override (default: os.environ).
    home:            Home directory override.
    filesystem_root: Filesystem root override.
    scan_proc:       Whether to scan /proc/*/environ (disabled by default).
    min_confidence:  Minimum confidence level to include.
    sources:         Source types to scan.  Defaults to ENV_VAR + FILESYSTEM
                     + KUBERNETES + CLOUD_IAM.
    path_exists_fn:  os.path.isfile override (injectable for testing).
    glob_fn:         glob.glob override (injectable for testing).

    Returns
    -------
    Dict with keys: candidates, total, by_source, by_confidence, by_nhi_type,
    discovery_version, discovered_at, evidence_origin.
    """
    active = set(sources or [
        SOURCE_ENV_VAR, SOURCE_FILESYSTEM, SOURCE_KUBERNETES, SOURCE_CLOUD_IAM,
    ])
    if scan_proc:
        active.add(SOURCE_PROC_ENV)

    all_candidates: list[dict[str, Any]] = []

    if SOURCE_ENV_VAR in active:
        all_candidates.extend(scan_environment_variables(env, min_confidence=min_confidence))

    if SOURCE_FILESYSTEM in active:
        all_candidates.extend(scan_filesystem_paths(
            home, root=filesystem_root, min_confidence=min_confidence,
            path_exists_fn=path_exists_fn, glob_fn=glob_fn,
        ))

    if SOURCE_KUBERNETES in active:
        all_candidates.extend(scan_kubernetes_service_accounts(path_exists_fn=path_exists_fn))

    if SOURCE_CLOUD_IAM in active:
        all_candidates.extend(scan_cloud_credentials(path_exists_fn=path_exists_fn))

    if SOURCE_PROC_ENV in active:
        all_candidates.extend(scan_proc_environments(min_confidence=min_confidence))

    # Deduplicate by nhi_id
    seen_ids: set = set()
    unique: list[dict[str, Any]] = []
    for c in all_candidates:
        nhi_id = c["nhi_id"]
        if nhi_id not in seen_ids:
            seen_ids.add(nhi_id)
            unique.append(c)

    by_source: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    by_nhi_type: dict[str, int] = {}
    for c in unique:
        by_source[c["source"]] = by_source.get(c["source"], 0) + 1
        by_confidence[c["confidence"]] = by_confidence.get(c["confidence"], 0) + 1
        by_nhi_type[c["nhi_type"]] = by_nhi_type.get(c["nhi_type"], 0) + 1

    return {
        "candidates": unique,
        "total": len(unique),
        "by_source": by_source,
        "by_confidence": by_confidence,
        "by_nhi_type": by_nhi_type,
        "evidence_origin": "LOCALLY_OBSERVED",
        "discovery_version": NHI_DISCOVERY_VERSION,
        "discovered_at": _utc_now(),
    }
