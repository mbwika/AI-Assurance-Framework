"""Immutable, digest-verifiable assurance report snapshots."""

import base64
import hashlib
import hmac
import json
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..reporting.assurance_report import build_assurance_report


SNAPSHOT_VERSION = "1.0"
SIGNATURE_ALGORITHM = "HMAC-SHA256"
ASYMMETRIC_SIGNATURE_ALGORITHM = "ED25519"


class AssuranceReportSnapshotEngine:
    def __init__(
        self,
        datastore: object,
        signing_key: Optional[str] = None,
        key_id: str = "default",
        signing_private_key_pem: Optional[str] = None,
        verification_public_key_pem: Optional[str] = None,
    ):
        self.datastore = datastore
        self.signing_key = signing_key or ""
        self.key_id = str(key_id or "default")
        self.signing_private_key_pem = _normalize_pem(signing_private_key_pem)
        self.verification_public_key_pem = _normalize_pem(verification_public_key_pem)

    def create(
        self,
        *,
        created_by: str,
        artifact_id: Optional[str] = None,
        model_id: Optional[str] = None,
        registered_by: Optional[str] = None,
        sign: bool = False,
    ) -> Dict[str, Any]:
        creator = str(created_by or "").strip()
        if not creator:
            raise ValueError("created_by is required")
        normalized_artifact = str(artifact_id or "").strip() or None
        normalized_model = str(model_id or "").strip() or None
        normalized_registrant = str(registered_by or "").strip() or None
        selected = [
            name
            for name, value in {
                "artifact_id": normalized_artifact,
                "model_id": normalized_model,
                "registered_by": normalized_registrant,
            }.items()
            if value
        ]
        if len(selected) > 1:
            raise ValueError(
                "Choose only one report scope filter: artifact_id, model_id, or registered_by"
            )
        if sign and not self._can_sign():
            raise ValueError(
                "A report signing key or signing private key is required for signed snapshots"
            )

        report = build_assurance_report(
            self.datastore,
            artifact_id=normalized_artifact,
            model_id=normalized_model,
            registered_by=normalized_registrant,
        )
        created_at = _utc_now()
        report_scope = report.get("scope") or {}
        snapshot_artifact = (
            normalized_model
            if report_scope.get("type") == "MODEL"
            else normalized_artifact
        )
        snapshot = {
            "id": str(uuid.uuid4()),
            "artifact_id": snapshot_artifact,
            "scope_type": report_scope.get("type", "PORTFOLIO"),
            "snapshot_version": SNAPSHOT_VERSION,
            "report_version": report.get("schema_version", "unknown"),
            "report": report,
            "sha256": _sha256_json(report),
            "signature": None,
            "signature_algorithm": None,
            "key_id": None,
            "created_by": creator,
            "created_at": created_at,
        }
        if sign:
            snapshot["key_id"] = self.key_id
            algorithm, signature = self._sign_snapshot(_signature_envelope(snapshot))
            snapshot["signature_algorithm"] = algorithm
            snapshot["signature"] = signature

        self.datastore.save_assurance_report_snapshot(snapshot)
        self.datastore.save_audit_log(
            {
                "event_type": "assurance_report_snapshot_created",
                "artifact_id": snapshot_artifact,
                "details": {
                    "snapshot_id": snapshot["id"],
                    "scope_type": snapshot["scope_type"],
                    "scope": report_scope,
                    "report_version": snapshot["report_version"],
                    "sha256": snapshot["sha256"],
                    "signed": bool(snapshot["signature"]),
                    "key_id": snapshot["key_id"],
                    "created_by": creator,
                },
            }
        )
        self.datastore.save_metric(
            "assurance_report_snapshot_created",
            1,
            {
                "artifact_id": snapshot_artifact,
                "scope_type": snapshot["scope_type"],
                "model_id": normalized_model,
                "registered_by": normalized_registrant,
                "signed": bool(snapshot["signature"]),
                "report_version": snapshot["report_version"],
            },
        )
        return snapshot

    def get(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        return self.datastore.get_assurance_report_snapshot(snapshot_id)

    def list(
        self,
        limit: int = 100,
        artifact_id: Optional[str] = None,
        model_id: Optional[str] = None,
        registered_by: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        normalized_artifact = str(artifact_id or "").strip() or None
        normalized_model = str(model_id or "").strip() or None
        normalized_registrant = str(registered_by or "").strip() or None
        snapshots = self.datastore.list_assurance_report_snapshots(
            limit=min(max(int(limit), 1), 1000),
            artifact_id=normalized_artifact or normalized_model,
        )
        if normalized_model:
            return [
                snapshot
                for snapshot in snapshots
                if (snapshot.get("report") or {}).get("scope", {}).get("model_id")
                == normalized_model
            ]
        if normalized_registrant:
            return [
                snapshot
                for snapshot in snapshots
                if (snapshot.get("report") or {}).get("scope", {}).get("registered_by")
                == normalized_registrant
            ]
        return snapshots

    def verify(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        snapshot = self.get(snapshot_id)
        if not snapshot:
            return None
        report = snapshot.get("report") or {}
        report_scope = report.get("scope") or {}
        signed = bool(snapshot.get("signature"))
        checks = {
            "report_digest_valid": hmac.compare_digest(
                str(snapshot.get("sha256") or ""), _sha256_json(report)
            ),
            "scope_type_matches": report_scope.get("type")
            == snapshot.get("scope_type"),
            "artifact_id_matches": report_scope.get("artifact_id")
            == snapshot.get("artifact_id"),
            "model_id_matches": report_scope.get("type") != "MODEL"
            or report_scope.get("model_id") == snapshot.get("artifact_id"),
            "registered_by_present": report_scope.get("type") != "REGISTRANT"
            or bool(report_scope.get("registered_by")),
            "report_version_matches": report.get("schema_version")
            == snapshot.get("report_version"),
            "snapshot_version_supported": snapshot.get("snapshot_version")
            == SNAPSHOT_VERSION,
            "supported_signature_algorithm": not signed
            or snapshot.get("signature_algorithm")
            in {SIGNATURE_ALGORITHM, ASYMMETRIC_SIGNATURE_ALGORITHM},
            "signing_key_present": not signed
            or self._has_verification_material(snapshot.get("signature_algorithm")),
            "key_id_matches": not signed or snapshot.get("key_id") == self.key_id,
            "signature_valid": not signed,
        }
        if (
            signed
            and checks["supported_signature_algorithm"]
            and checks["signing_key_present"]
        ):
            checks["signature_valid"] = self._verify_signature(
                _signature_envelope(snapshot),
                str(snapshot.get("signature_algorithm") or ""),
                str(snapshot.get("signature") or ""),
            )
        verified = all(checks.values())
        result = {
            "snapshot_id": snapshot_id,
            "verified": verified,
            "signed": signed,
            "sha256": snapshot.get("sha256"),
            "checks": checks,
        }
        self.datastore.save_audit_log(
            {
                "event_type": "assurance_report_snapshot_verified",
                "artifact_id": snapshot.get("artifact_id"),
                "details": result,
            }
        )
        return result

    def _can_sign(self) -> bool:
        return bool(self.signing_private_key_pem or self.signing_key)

    def _sign_snapshot(self, value: Dict[str, Any]) -> tuple[str, str]:
        if self.signing_private_key_pem:
            return (
                ASYMMETRIC_SIGNATURE_ALGORITHM,
                _sign_ed25519(value, self.signing_private_key_pem),
            )
        return SIGNATURE_ALGORITHM, _sign_hmac(value, self.signing_key)

    def _has_verification_material(self, algorithm: Optional[str]) -> bool:
        algorithm = str(algorithm or "")
        if algorithm == ASYMMETRIC_SIGNATURE_ALGORITHM:
            return bool(self.verification_public_key_pem or self.signing_private_key_pem)
        if algorithm == SIGNATURE_ALGORITHM:
            return bool(self.signing_key)
        return False

    def _verify_signature(
        self, value: Dict[str, Any], algorithm: str, signature: str
    ) -> bool:
        if algorithm == SIGNATURE_ALGORITHM:
            expected = _sign_hmac(value, self.signing_key)
            return hmac.compare_digest(signature, expected)
        if algorithm == ASYMMETRIC_SIGNATURE_ALGORITHM:
            public_pem = self.verification_public_key_pem or _derive_public_pem(
                self.signing_private_key_pem
            )
            if not public_pem:
                return False
            return _verify_ed25519(value, signature, public_pem)
        return False


def _signature_envelope(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "snapshot_version": snapshot["snapshot_version"],
        "snapshot_id": snapshot["id"],
        "artifact_id": snapshot.get("artifact_id"),
        "scope_type": snapshot["scope_type"],
        "report_version": snapshot["report_version"],
        "report_sha256": snapshot["sha256"],
        "created_by": snapshot["created_by"],
        "created_at": snapshot["created_at"],
        "key_id": snapshot.get("key_id"),
    }


def _sign_hmac(value: Dict[str, Any], signing_key: str) -> str:
    return hmac.new(
        signing_key.encode("utf-8"), _canonical_json(value), hashlib.sha256
    ).hexdigest()


def _sign_ed25519(value: Dict[str, Any], private_key_pem: str) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Expected an Ed25519 private key for report signing")
        signature = private_key.sign(_canonical_json(value))
        return base64.b64encode(signature).decode("ascii")
    except ImportError:
        return _openssl_sign_ed25519(value, private_key_pem)


def _verify_ed25519(value: Dict[str, Any], signature: str, public_key_pem: str) -> bool:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(base64.b64decode(signature.encode("ascii")), _canonical_json(value))
        return True
    except ImportError:
        return _openssl_verify_ed25519(value, signature, public_key_pem)
    except Exception:
        return False


def _derive_public_pem(private_key_pem: Optional[str]) -> str:
    if not private_key_pem:
        return ""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            return ""
        return (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
    except ImportError:
        return _openssl_derive_public_pem(private_key_pem)


def _openssl_sign_ed25519(value: Dict[str, Any], private_key_pem: str) -> str:
    with tempfile.TemporaryDirectory(prefix="aiaf_snap_sig_") as tmp:
        key_path = f"{tmp}/signing-key.pem"
        data_path = f"{tmp}/payload.bin"
        with open(key_path, "w", encoding="utf-8") as handle:
            handle.write(private_key_pem)
        with open(data_path, "wb") as handle:
            handle.write(_canonical_json(value))
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key_path, "-in", data_path],
            check=True,
            capture_output=True,
        )
        return base64.b64encode(result.stdout).decode("ascii")


def _openssl_verify_ed25519(value: Dict[str, Any], signature: str, public_key_pem: str) -> bool:
    try:
        with tempfile.TemporaryDirectory(prefix="aiaf_snap_verify_") as tmp:
            key_path = f"{tmp}/verify-key.pem"
            data_path = f"{tmp}/payload.bin"
            sig_path = f"{tmp}/payload.sig"
            with open(key_path, "w", encoding="utf-8") as handle:
                handle.write(public_key_pem)
            with open(data_path, "wb") as handle:
                handle.write(_canonical_json(value))
            with open(sig_path, "wb") as handle:
                handle.write(base64.b64decode(signature.encode("ascii")))
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    key_path,
                    "-sigfile",
                    sig_path,
                    "-in",
                    data_path,
                ],
                check=True,
                capture_output=True,
            )
        return True
    except Exception:
        return False


def _openssl_derive_public_pem(private_key_pem: str) -> str:
    try:
        with tempfile.TemporaryDirectory(prefix="aiaf_snap_pub_") as tmp:
            key_path = f"{tmp}/private.pem"
            with open(key_path, "w", encoding="utf-8") as handle:
                handle.write(private_key_pem)
            result = subprocess.run(
                ["openssl", "pkey", "-in", key_path, "-pubout"],
                check=True,
                capture_output=True,
                text=True,
            )
        return result.stdout
    except Exception:
        return ""


def _sha256_json(value: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_pem(value: Optional[str]) -> str:
    if not value:
        return ""
    return str(value).replace("\\n", "\n").strip()
