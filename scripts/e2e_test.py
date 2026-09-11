import argparse
import json
import sys
import urllib.error
import urllib.request

import boto3


EXPECTED_ANALYSIS_KEYS = {
    "verdict",
    "confidence",
    "scam_family",
    "scam_family_label",
    "headline",
    "red_flags",
    "what_to_do",
    "what_scammer_wants",
    "message_language",
    "demo_mode",
    "check_id",
}


def _request(url: str, method: str, payload: dict | None = None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Origin": "https://example.com"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = "POST"
        headers["Access-Control-Request-Headers"] = "content-type"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


def _header(headers: dict[str, str], name: str) -> str:
    return next(
        (value for key, value in headers.items() if key.lower() == name.lower()),
        "",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Test the deployed ScamBuster API.")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--table-name", required=True)
    args = parser.parse_args()
    url = f"{args.endpoint.rstrip('/')}/analyze"
    results = []

    status, _, response_body = _request(
        url,
        "POST",
        {
            "text": (
                "Final notice: your toll payment is overdue. Pay now at "
                "https://fastag-pay-now.example or face a penalty."
            )
        },
    )
    analysis = json.loads(response_body)
    schema_passed = (
        status == 200
        and analysis.get("demo_mode") is True
        and EXPECTED_ANALYSIS_KEYS.issubset(analysis)
    )
    results.append(("200 schema+demo_mode", schema_passed))

    status, _, _ = _request(url, "POST", {})
    results.append(("400 empty", status == 400))

    status, _, _ = _request(url, "POST", {"text": "x" * 10_001})
    results.append(("400 oversize", status == 400))

    status, headers, _ = _request(url, "OPTIONS")
    cors_passed = (
        status in {200, 204}
        and _header(headers, "Access-Control-Allow-Origin") == "*"
        and "POST" in _header(headers, "Access-Control-Allow-Methods")
        and "content-type" in _header(
            headers, "Access-Control-Allow-Headers"
        ).lower()
    )
    results.append(("CORS preflight", cors_passed))

    item = None
    if analysis.get("check_id"):
        table = boto3.resource("dynamodb", region_name="us-east-1").Table(
            args.table_name
        )
        item = table.get_item(
            Key={"id": analysis["check_id"]},
            ConsistentRead=True,
        ).get("Item")
    stored_fields = {
        "id",
        "created_at",
        "verdict",
        "confidence",
        "scam_family",
        "red_flag_types",
        "message_language",
        "input_kind",
        "demo_mode",
    }
    dynamodb_passed = item is not None and set(item) == stored_fields
    results.append(("DynamoDB item verified", dynamodb_passed))

    for name, passed in results:
        print(f"{name}: {'PASS' if passed else 'FAIL'}")
    all_passed = all(passed for _, passed in results)
    print(f"E2E SUMMARY: {'PASS' if all_passed else 'FAIL'}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
