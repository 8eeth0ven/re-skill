"""S3 adapter: real PUT/GET/error-code exercise against a local moto endpoint.

This is a REAL network exercise (live HTTP round-trips over 127.0.0.1) but
against an in-process moto S3 emulation server, not AWS. The record therefore
labels ``service`` explicitly: "local in-process moto S3 endpoint (not AWS)".
When moto/boto3 cannot be imported the probe reports "not-run" — it never
fabricates a pass.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

from .safety import atomic_json, redact

PROBE_BODY = b"re-blane-s3-probe-evidence\n"


def _base_record(argv: list[str]) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "id": f"toolrun-{uuid.uuid4().hex[:12]}",
        "asset_id": "blane-object-storage-local",
        "tool": "s3-adapter",
        "version": "moto/boto3",
        "argv": argv,
        "status": "failed",
        "started": now,
        "finished": now,
        "exit_code": None,
        "artifacts": [],
        "error": None,
        "verification_state": "real-run",
        "service": "local in-process moto S3 endpoint (not AWS)",
    }


def s3_probe(output_dir: Path, *, bucket: str = "re-blane-bucket", key: str = "probe/evidence.txt") -> dict:
    """Create bucket, PUT, GET back, then assert both failure codes (NoSuchKey, NoSuchBucket)."""
    try:
        import boto3  # noqa: PLC0415
        from botocore.client import Config  # noqa: PLC0415
        from botocore.exceptions import ClientError  # noqa: PLC0415
        from moto.server import ThreadedMotoServer  # noqa: PLC0415
    except Exception as exc:
        return {
            **_base_record(["s3-probe"]),
            "status": "not-run",
            "verification_state": "not-run",
            "error": f"moto/boto3 unavailable: {exc}",
        }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    record = _base_record(["s3-probe", bucket, key])
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0)
    server.start()
    ops: list[dict] = []
    try:
        port = server._server.server_port  # noqa: SLF001 - moto exposes no public accessor
        endpoint = f"http://127.0.0.1:{port}"
        record["endpoint"] = endpoint
        client = boto3.client(
            "s3", endpoint_url=endpoint, region_name="us-east-1",
            aws_access_key_id="testing", aws_secret_access_key="testing",
            config=Config(s3={"addressing_style": "path"}),
        )
        client.create_bucket(Bucket=bucket)
        ops.append({"op": "create_bucket", "status": "succeeded"})

        client.put_object(Bucket=bucket, Key=key, Body=PROBE_BODY)
        ops.append({"op": "put_object", "status": "succeeded", "bytes": len(PROBE_BODY)})

        fetched = client.get_object(Bucket=bucket, Key=key)["Body"].read()
        roundtrip_ok = fetched == PROBE_BODY
        ops.append({"op": "get_object", "status": "succeeded" if roundtrip_ok else "failed",
                    "roundtrip_equal": roundtrip_ok})

        missing_key_error = None
        try:
            client.get_object(Bucket=bucket, Key="does/not/exist")
        except ClientError as exc:
            missing_key_error = exc.response.get("Error", {}).get("Code", "")
        ops.append({"op": "get_object_missing_key", "status": "succeeded" if missing_key_error else "failed",
                    "error_code": missing_key_error})

        missing_bucket_error = None
        try:
            client.get_object(Bucket="re-blane-no-such-bucket", Key=key)
        except ClientError as exc:
            missing_bucket_error = exc.response.get("Error", {}).get("Code", "")
        ops.append({"op": "get_object_missing_bucket", "status": "succeeded" if missing_bucket_error else "failed",
                    "error_code": missing_bucket_error})

        succeeded_ops = sum(1 for op in ops if op["status"] == "succeeded")
        record.update({
            "operations": ops,
            "status": "succeeded" if succeeded_ops == len(ops) and roundtrip_ok else "degraded",
            "exit_code": 0,
        })
    except Exception as exc:
        record["operations"] = ops
        record["error"] = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        server.stop()
        record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_json(output_dir / "s3-probe.json", redact(record))
    record["artifacts"].append({"path": str(output_dir / "s3-probe.json"), "kind": "json"})
    return record
