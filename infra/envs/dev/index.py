import json
import logging
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Defer kinesis client creation to POST path so /health (GET) never touches it
_kinesis_client = None


def _get_kinesis_client():
    global _kinesis_client
    if _kinesis_client is None:
        _kinesis_client = boto3.client("kinesis")
    return _kinesis_client


def _json_response(status: int, body: dict) -> dict:
    """Standard Lambda proxy response with CORS."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
        "isBase64Encoded": False,
    }


def validate_event_schema(event_data):
    """Basic event validation"""
    required_fields = ["source", "actor", "action", "resource"]
    for field in required_fields:
        if field not in event_data:
            return False, f"Missing required field: {field}"
    return True, None


def normalize_event(raw_event, source_ip):
    """Normalize event to standard format"""
    event_id = raw_event.get("event_id", str(uuid.uuid4()))

    actor = raw_event.get("actor", {})
    if "ip" not in actor and source_ip:
        actor["ip"] = source_ip

    normalized = {
        "event_id": event_id,
        "source": raw_event.get("source"),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": raw_event.get("action"),
        "resource": raw_event.get("resource"),
        "severity_hint": raw_event.get("severity_hint", 1),
        "payload": raw_event.get("payload", {}),
        "schema_ver": "1.0",
    }
    return normalized


def send_to_kinesis(event):
    """Send event to Kinesis stream"""
    try:
        stream_name = os.environ.get("KINESIS_STREAM_NAME")
        if not stream_name:
            # For dev, don't crash the whole request if the env var is missing.
            logger.warning("KINESIS_STREAM_NAME is not set; skipping Kinesis publish")
            return True

        partition_key = f"{event.get('actor', {}).get('id', 'unknown')}#{event.get('source', 'unknown')}"
        client = _get_kinesis_client()
        client.put_record(StreamName=stream_name, Data=json.dumps(event), PartitionKey=partition_key)
        logger.info(f"Event sent to Kinesis: {event.get('event_id')}")
        return True
    except (BotoCoreError, ClientError, Exception) as e:
        logger.error(f"Error sending to Kinesis: {str(e)}")
        return False


def lambda_handler(event, context):
    """Main Lambda handler (REST API proxy)."""
    # Log safely; event can contain non-serializable types
    try:
        logger.info("Received event: %s", json.dumps(event, default=str))
    except Exception:
        logger.info("Received event (unserializable)")

    # Tolerate differences in event shapes
    path = (event or {}).get("path") or ""
    http_method = (event or {}).get("httpMethod") or "GET"

    # Health: respond OK to GET /health (and, for convenience, any GET)
    if http_method.upper() == "GET":
        # If you want to restrict to only /health, change condition to: path.endswith("/health")
        return _json_response(
            200,
            {
                "status": "healthy",
                "service": "secureops360-ingest",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "1.0.0",
                "path": path,
            },
        )

    if http_method.upper() != "POST":
        return _json_response(405, {"error": "Method not allowed"})

    # Source IP (REST API v1 shape)
    source_ip = (event.get("requestContext", {}).get("identity", {}) or {}).get("sourceIp")

    # Parse body
    body = event.get("body", "{}")
    if isinstance(body, str):
        try:
            body = json.loads(body or "{}")
        except json.JSONDecodeError:
            return _json_response(400, {"error": "Invalid JSON format"})

    # Accept single event object or list of events
    events_to_process = [body] if isinstance(body, dict) else (body if isinstance(body, list) else [])

    processed_events = []
    errors = []

    for i, raw_event in enumerate(events_to_process):
        try:
            is_valid, error_msg = validate_event_schema(raw_event)
            if not is_valid:
                errors.append(
                    {"index": i, "error": error_msg, "event_id": raw_event.get("event_id", "unknown")}
                )
                continue

            normalized_event = normalize_event(raw_event, source_ip)
            success = send_to_kinesis(normalized_event)

            if success:
                processed_events.append({"event_id": normalized_event["event_id"], "status": "accepted"})
            else:
                errors.append(
                    {"index": i, "error": "Failed to send to stream", "event_id": normalized_event["event_id"]}
                )

        except Exception as e:
            errors.append({"index": i, "error": str(e), "event_id": raw_event.get("event_id", "unknown")})

    response_body = {
        "processed": len(processed_events),
        "errors": len(errors),
        "events": processed_events,
    }
    if errors:
        response_body["errors_detail"] = errors

    status_code = 200 if not errors else 207
    return _json_response(status_code, response_body)
