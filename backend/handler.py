import base64
import binascii
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3

from analyzer import AnalysisError, analyze_message


MAX_TEXT_LENGTH = 10_000
MAX_IMAGE_BYTES = 4 * 1024 * 1024
IMAGE_FORMATS = {"png", "jpeg", "webp"}
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Content-Type": "application/json",
}
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
_TABLE = None


class RequestValidationError(Exception):
    """Raised when an API request body is invalid."""


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body),
    }


def _parse_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if isinstance(body, dict):
        return body
    if not isinstance(body, str):
        raise RequestValidationError("Request body must be a JSON object.")

    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as error:
            raise RequestValidationError("Request body is not valid base64 JSON.") from error

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise RequestValidationError("Request body must contain valid JSON.") from error
    if not isinstance(payload, dict):
        raise RequestValidationError("Request body must be a JSON object.")
    return payload


def _validate_payload(
    payload: dict[str, Any],
) -> tuple[str | None, bytes | None, str | None]:
    text = payload.get("text")
    if text is not None and not isinstance(text, str):
        raise RequestValidationError("text must be a string.")
    if text is not None and len(text) > MAX_TEXT_LENGTH:
        raise RequestValidationError("text must be at most 10000 characters.")

    image_base64 = payload.get("image_base64")
    image_format = payload.get("image_format")
    image_bytes = None

    if image_base64 is not None:
        if not isinstance(image_base64, str) or not image_base64:
            raise RequestValidationError("image_base64 must be a non-empty string.")
        if image_format not in IMAGE_FORMATS:
            raise RequestValidationError(
                "image_format must be one of: png, jpeg, webp."
            )
        try:
            image_bytes = base64.b64decode(image_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise RequestValidationError("image_base64 is not valid base64.") from error
        if len(image_bytes) > MAX_IMAGE_BYTES:
            raise RequestValidationError("Decoded image must be at most 4 MB.")
    elif image_format is not None:
        raise RequestValidationError("image_format requires image_base64.")

    if not text and image_bytes is None:
        raise RequestValidationError("At least one of text or image_base64 is required.")
    return text, image_bytes, image_format


def _get_table():
    global _TABLE
    if _TABLE is None:
        table_name = os.environ["TABLE_NAME"]
        _TABLE = boto3.resource("dynamodb", region_name="us-east-1").Table(table_name)
    return _TABLE


def _input_kind(text: str | None, image_bytes: bytes | None) -> str:
    if text and image_bytes is not None:
        return "both"
    if image_bytes is not None:
        return "image"
    return "text"


def _write_analysis_log(
    analysis: dict[str, Any],
    text: str | None,
    image_bytes: bytes | None,
) -> str:
    check_id = str(uuid.uuid4())
    red_flag_types = [
        red_flag["type"]
        for red_flag in analysis.get("red_flags", [])
        if isinstance(red_flag, dict) and isinstance(red_flag.get("type"), str)
    ]
    _get_table().put_item(
        Item={
            "id": check_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "verdict": analysis["verdict"],
            "confidence": int(analysis["confidence"]),
            "scam_family": analysis["scam_family"],
            "red_flag_types": red_flag_types,
            "message_language": analysis.get("message_language", "unknown"),
            "input_kind": _input_kind(text, image_bytes),
            "engine": analysis.get("engine", "unknown"),
            "demo_mode": bool(analysis.get("demo_mode", False)),
        }
    )
    return check_id


def lambda_handler(event, context):
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
    )
    if method == "OPTIONS":
        return _response(204, {})

    try:
        payload = _parse_body(event)
        text, image_bytes, image_format = _validate_payload(payload)
    except RequestValidationError as error:
        return _response(400, {"error": str(error)})

    try:
        analysis = analyze_message(text, image_bytes, image_format)
        try:
            check_id = _write_analysis_log(analysis, text, image_bytes)
            analysis["check_id"] = check_id
        except Exception:
            LOGGER.exception("Failed to write anonymized analysis log")
        return _response(200, analysis)
    except AnalysisError:
        LOGGER.exception("Analysis failed")
        return _response(502, {"error": "analysis_failed"})
    except Exception:
        LOGGER.exception("Analysis failed")
        return _response(502, {"error": "analysis_failed"})
