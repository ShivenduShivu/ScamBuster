import json
import os
import re
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from prompts import ANALYSIS_SYSTEM_PROMPT
from rules_engine import analyze_rules


REGION = "us-east-1"
DEFAULT_MODEL_ID = "amazon.nova-2-lite-v1:0"
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID)
FALLBACK_MODEL_ID = "amazon.nova-lite-v1:0"
ANALYSIS_MODE = os.environ.get("ANALYSIS_MODE", "bedrock")

_REQUIRED_KEYS = {
    "verdict",
    "confidence",
    "scam_family",
    "scam_family_label",
    "headline",
}
_OPTIONAL_DEFAULTS = {
    "red_flags": [],
    "what_to_do": [],
    "what_scammer_wants": None,
    "message_language": "unknown",
}
_CLIENT = None


class AnalysisError(Exception):
    """Raised when a model response cannot be converted into a valid analysis."""


def _mock_analysis() -> dict[str, Any]:
    return {
        "verdict": "likely_scam",
        "confidence": 88,
        "scam_family": "toll_or_fine_smishing",
        "scam_family_label": "Fake toll payment scam",
        "headline": (
            "[DEMO MODE] This message matches a likely fake toll payment scam."
        ),
        "red_flags": [
            {
                "type": "urgency_pressure",
                "evidence": "Pay immediately to avoid a penalty",
                "explanation": (
                    "Artificial urgency is commonly used to prevent careful verification."
                ),
            },
            {
                "type": "suspicious_link",
                "evidence": "https://fastag-payment.example",
                "explanation": (
                    "The payment link does not use an official toll-service domain."
                ),
            },
        ],
        "what_to_do": [
            "Do not click the link",
            "Do not make a payment",
            "Verify any toll balance through the official app or website",
            "Block and report the sender",
        ],
        "what_scammer_wants": (
            "The sender wants to steal payment details or collect a fraudulent fee."
        ),
        "message_language": "English",
        "engine": "mock",
        "demo_mode": True,
    }


def _get_client():
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = boto3.client(
            "bedrock-runtime",
            region_name=REGION,
            config=Config(retries={"total_max_attempts": 3, "mode": "adaptive"}),
        )
    return _CLIENT


def _invoke_model(content: list[dict[str, Any]], model_id: str) -> str:
    response = _get_client().converse(
        modelId=model_id,
        system=[{"text": ANALYSIS_SYSTEM_PROMPT}],
        messages=[{"role": "user", "content": content}],
        inferenceConfig={"maxTokens": 1000, "temperature": 0.2},
    )
    blocks = response["output"]["message"]["content"]
    text = "".join(block.get("text", "") for block in blocks).strip()
    if not text:
        raise AnalysisError("Bedrock returned an empty response.")
    return text


def _is_model_resolution_error(error: ClientError) -> bool:
    details = error.response.get("Error", {})
    code = details.get("Code", "")
    message = details.get("Message", "").lower()
    return code in {"ValidationException", "ResourceNotFoundException"} or (
        "model" in message and "not found" in message
    )


def _invoke_with_fallback(content: list[dict[str, Any]]) -> tuple[str, str]:
    try:
        return _invoke_model(content, MODEL_ID), MODEL_ID
    except ClientError as error:
        if MODEL_ID == DEFAULT_MODEL_ID and _is_model_resolution_error(error):
            return _invoke_model(content, FALLBACK_MODEL_ID), FALLBACK_MODEL_ID
        raise


def _parse_json(raw_output: str) -> dict[str, Any]:
    candidate = raw_output.strip()
    candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"\s*```$", "", candidate)
    parsed = json.loads(candidate)
    if not isinstance(parsed, dict):
        raise ValueError("Model output is not a JSON object.")
    return parsed


def _validate_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    missing = sorted(_REQUIRED_KEYS - analysis.keys())
    if missing:
        raise AnalysisError(
            f"Model response is missing required fields: {', '.join(missing)}."
        )

    for key, default in _OPTIONAL_DEFAULTS.items():
        if key not in analysis:
            analysis[key] = default.copy() if isinstance(default, list) else default
    return analysis


def analyze_message(
    text: str | None,
    image_bytes: bytes | None,
    image_format: str | None,
) -> dict:
    if ANALYSIS_MODE not in {"bedrock", "mock", "rules"}:
        raise AnalysisError(
            "ANALYSIS_MODE must be 'bedrock', 'mock', or 'rules'."
        )
    if not text and image_bytes is None:
        raise AnalysisError("Text or image content is required for analysis.")
    if image_bytes is not None and not image_format:
        raise AnalysisError("An image format is required when image bytes are supplied.")
    if ANALYSIS_MODE == "mock":
        return _mock_analysis()
    if ANALYSIS_MODE == "rules":
        return analyze_rules(text, image_bytes, image_format)

    content: list[dict[str, Any]] = []
    if text:
        content.append({"text": f"Analyze this message the user received: {text}"})
    if image_bytes is not None:
        content.append(
            {
                "image": {
                    "format": image_format,
                    "source": {"bytes": image_bytes},
                }
            }
        )
    raw_output, model_id = _invoke_with_fallback(content)
    try:
        analysis = _parse_json(raw_output)
    except (json.JSONDecodeError, ValueError):
        retry_content = [*content, {"text": "Output only the raw JSON object."}]
        retry_output = _invoke_model(retry_content, model_id)
        try:
            analysis = _parse_json(retry_output)
        except (json.JSONDecodeError, ValueError) as error:
            raise AnalysisError(
                "Bedrock returned invalid JSON after one corrective retry."
            ) from error

    validated = _validate_analysis(analysis)
    validated["engine"] = "bedrock"
    validated["demo_mode"] = False
    return validated
