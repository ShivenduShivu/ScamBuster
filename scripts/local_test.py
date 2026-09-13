import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from rules_engine import analyze_rules


CASES = [
    {
        "name": "Fake toll payment",
        "text": (
            "Final Notice: Your FASTag toll payment of Rs 25 is overdue. Pay "
            "immediately at https://fastag-pay-now.xyz or face a Rs 5000 penalty."
        ),
        "expected": {"scam", "likely_scam"},
    },
    {
        "name": "Fake job registration fee",
        "text": (
            "Congratulations! You are selected for Data Entry Executive. Pay Rs "
            "1500 registration fee today. Contact HR at "
            "careers.quickhire@gmail.com to confirm."
        ),
        "expected": {"scam", "likely_scam"},
    },
    {
        "name": "Delivery customs fee",
        "text": (
            "India Post: Your parcel is held at customs. Pay Rs 49 customs fee "
            "now at http://indiapost-track.help/parcel to avoid return."
        ),
        "expected": {"scam", "likely_scam"},
    },
    {
        "name": "Legitimate OTP",
        "text": "Your HDFC Bank OTP is 482913. Do not share with anyone.",
        "expected": {"likely_legitimate"},
    },
    {
        "name": "Personal message",
        "text": "Hey, running 10 min late, order the coffee",
        "expected": {"likely_legitimate"},
    },
    {
        "name": "Hinglish task scam",
        "text": (
            "Work from home: har task par Rs 500 kamao. Registration shulk Rs "
            "1200 abhi bhugtan karo aur Telegram HR ko jaldi message karo."
        ),
        "expected": {"scam", "likely_scam"},
    },
    {
        "name": "Legitimate Amazon order",
        "text": (
            "Your Amazon.in order has been confirmed and will arrive Tuesday. "
            "Track it at https://www.amazon.in/gp/your-account/order-history"
        ),
        "expected": {"likely_legitimate"},
    },
    {
        "name": "Empty-ish input",
        "text": "...",
        "expected": {"insufficient_content"},
    },
]


def _image_format(path: Path) -> str:
    formats = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".webp": "webp"}
    try:
        return formats[path.suffix.lower()]
    except KeyError as error:
        raise ValueError("Image must be a PNG, JPEG, or WebP file.") from error


def _print_analysis(name: str, analysis: dict) -> None:
    print(f"{name}: {analysis['verdict']} ({analysis['confidence']}%) - {analysis['scam_family']}")


def _evidence_is_exact(text: str, analysis: dict) -> bool:
    return all(red_flag.get("evidence", "") in text for red_flag in analysis["red_flags"])


def _run_built_in_cases() -> bool:
    passed = 0
    for case in CASES:
        analysis = analyze_rules(case["text"])
        _print_analysis(case["name"], analysis)
        case_passed = (
            analysis["verdict"] in case["expected"]
            and analysis["engine"] == "rules"
            and analysis["demo_mode"] is False
            and _evidence_is_exact(case["text"], analysis)
        )
        print(f"  verdict, engine, and exact-evidence checks: {'PASS' if case_passed else 'FAIL'}")
        passed += int(case_passed)

    all_passed = passed == len(CASES)
    print(f"RULES SUMMARY: {'PASS' if all_passed else 'FAIL'} ({passed}/{len(CASES)})")
    return all_passed


def _run_ad_hoc(text: str | None, image_path: str | None) -> None:
    image_bytes = None
    image_format = None
    if image_path:
        path = Path(image_path)
        image_bytes = path.read_bytes()
        image_format = _image_format(path)
    analysis = analyze_rules(text, image_bytes, image_format)
    _print_analysis("Ad-hoc analysis", analysis)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the rule-based analyzer locally.")
    parser.add_argument("--text", help="Message text to analyze.")
    parser.add_argument("--image", help="Path to a PNG, JPEG, or WebP screenshot.")
    args = parser.parse_args()

    try:
        if args.text is not None or args.image is not None:
            _run_ad_hoc(args.text, args.image)
            return 0
        return 0 if _run_built_in_cases() else 1
    except (OSError, ValueError) as error:
        print(f"Test error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
