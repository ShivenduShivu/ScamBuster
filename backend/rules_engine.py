import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


FAMILY_LABELS = {
    "delivery_smishing": "Fake delivery or customs fee scam",
    "toll_or_fine_smishing": "Fake toll or fine scam",
    "bank_or_upi_phishing": "Bank or UPI phishing",
    "job_or_task_scam": "Job or task scam",
    "government_imposter": "Government impostor scam",
    "family_emergency_imposter": "Family emergency impostor scam",
    "investment_or_crypto": "Investment or cryptocurrency scam",
    "romance_scam": "Romance scam",
    "lottery_or_prize": "Lottery or prize scam",
    "tech_support": "Tech support scam",
    "rental_or_deposit_fraud": "Rental or deposit fraud",
    "subscription_or_billing": "Subscription or billing scam",
    "sextortion": "Sextortion scam",
    "account_takeover_phishing": "Account takeover phishing",
    "other_scam": "Other suspected scam",
    "not_scam": "No specific scam pattern",
}

REPORT_ACTION = (
    "Report suspected fraud at reportfraud.ftc.gov (US) or "
    "cybercrime.gov.in (India)"
)

FAMILY_ACTIONS = {
    "delivery_smishing": [
        "Do not pay through the message link",
        "Check the shipment in the carrier's official app or website",
        "Contact the carrier using a verified support channel",
        REPORT_ACTION,
    ],
    "toll_or_fine_smishing": [
        "Do not click the payment link",
        "Check fines through the official transport or toll portal",
        "Do not enter card or banking details",
        REPORT_ACTION,
    ],
    "bank_or_upi_phishing": [
        "Do not share an OTP, PIN, password, CVV, or card number",
        "Open your bank's official app instead of using message links",
        "Call the number printed on your card if you are concerned",
        REPORT_ACTION,
    ],
    "job_or_task_scam": [
        "Do not pay a registration, training, or task fee",
        "Verify the employer through its official corporate website",
        "Stop contact with recruiters who demand deposits",
        REPORT_ACTION,
    ],
    "government_imposter": [
        "Do not pay or share personal information",
        "End the call or chat and contact the agency independently",
        "Preserve the message for an official report",
        REPORT_ACTION,
    ],
    "family_emergency_imposter": [
        "Contact your relative on a previously known number",
        "Ask a question only the real person would know",
        "Do not send money until you verify the situation",
        REPORT_ACTION,
    ],
    "investment_or_crypto": [
        "Do not transfer money or cryptocurrency",
        "Verify the firm with the relevant financial regulator",
        "Ignore screenshots or dashboards claiming guaranteed profit",
        REPORT_ACTION,
    ],
    "romance_scam": [
        "Do not send money, gift cards, or cryptocurrency",
        "Reverse-search profile images and verify the person's identity",
        "Tell someone you trust before taking financial action",
        REPORT_ACTION,
    ],
    "lottery_or_prize": [
        "Do not pay a fee to claim the prize",
        "Do not share banking or identity information",
        "Verify the promotion on the organizer's official website",
        REPORT_ACTION,
    ],
    "tech_support": [
        "Do not install remote-access software",
        "Close the message and contact official product support",
        "Run a security scan from software you already trust",
        REPORT_ACTION,
    ],
    "rental_or_deposit_fraud": [
        "Do not send a deposit before viewing and verifying the property",
        "Confirm ownership and the agent's identity independently",
        "Use a traceable payment method with buyer protection",
        REPORT_ACTION,
    ],
    "subscription_or_billing": [
        "Do not call numbers or use links in the invoice",
        "Check subscriptions through the provider's official account page",
        "Review payment activity directly with your bank",
        REPORT_ACTION,
    ],
    "sextortion": [
        "Do not pay or continue negotiating",
        "Save evidence and block the sender",
        "Report the threat to the platform and local authorities",
        REPORT_ACTION,
    ],
    "account_takeover_phishing": [
        "Do not use the login link in the message",
        "Open the service directly and review account security",
        "Change your password and enable multi-factor authentication if needed",
        REPORT_ACTION,
    ],
    "other_scam": [
        "Do not send money or personal information",
        "Verify the sender using an independent official channel",
        "Save the message and block the sender",
        REPORT_ACTION,
    ],
    "not_scam": [
        "Use the organization's official app or website for sensitive actions",
        "Never share an OTP, PIN, password, or CVV",
        "If the context seems wrong, verify the message independently",
        REPORT_ACTION,
    ],
}

ALLOWED_DOMAINS = {
    "amazon.com",
    "amazon.in",
    "apple.com",
    "axisbank.com",
    "dhl.com",
    "fedex.com",
    "flipkart.com",
    "google.com",
    "hdfcbank.com",
    "icicibank.com",
    "india.gov.in",
    "indiapost.gov.in",
    "incometax.gov.in",
    "microsoft.com",
    "netflix.com",
    "paypal.com",
    "sbi.co.in",
    "tollguru.com",
    "ups.com",
    "usps.com",
}

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy"}
MULTIPART_SUFFIXES = {"co.in", "co.uk", "com.au", "com.br", "co.jp", "gov.in"}
FREE_MAIL_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
}

BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "india post": {"indiapost.gov.in"},
    "microsoft": {"microsoft.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "sbi": {"sbi.co.in"},
    "usps": {"usps.com"},
}

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CURRENCY_AMOUNT = r"(?:₹|Rs\.?|INR|USD|\$)\s*\d[\d,]*(?:\.\d{1,2})?"
PAYMENT_WORDS = (
    r"fee|fees|deposit|registration|training|unlock|customs|penalty|fine|"
    r"renew|renewal|payment|pay|paid|charge|charges|भुगतान|शुल्क|जुर्माना|फीस|"
    r"bhugtan|shulk"
)


@dataclass(frozen=True)
class Signal:
    flag_type: str
    evidence: str
    explanation: str
    strong: bool


def _registrable_domain(hostname: str) -> str:
    host = hostname.lower().strip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return host
    suffix = ".".join(labels[-2:])
    if suffix in MULTIPART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def _url_details(raw_url: str) -> tuple[str, str]:
    cleaned = raw_url.rstrip(".,!?;:)]}")
    parsed = urlsplit(cleaned if "://" in cleaned else f"http://{cleaned}")
    return cleaned, (parsed.hostname or "").lower()


def _looks_like_brand(hostname: str) -> bool:
    translation = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
    for label in hostname.split("."):
        if not any(character.isdigit() for character in label):
            continue
        normalized = label.translate(translation)
        if any(brand.replace(" ", "") in normalized for brand in BRAND_DOMAINS):
            return True
    return False


def _add_signal(
    signals: list[Signal],
    flag_type: str,
    evidence: str,
    explanation: str,
    strong: bool,
) -> None:
    normalized = evidence.strip()
    if not normalized:
        return
    key = (flag_type, normalized.casefold())
    if any((item.flag_type, item.evidence.casefold()) == key for item in signals):
        return
    signals.append(Signal(flag_type, normalized, explanation, strong))


def _add_pattern_matches(
    signals: list[Signal],
    text: str,
    pattern: str,
    flag_type: str,
    explanation: str,
    strong: bool,
) -> None:
    for match in re.finditer(pattern, text, re.IGNORECASE | re.UNICODE):
        _add_signal(signals, flag_type, match.group(0), explanation, strong)


def _detect_urls(text: str, signals: list[Signal]) -> list[tuple[str, str, str]]:
    urls = []
    for match in URL_PATTERN.finditer(text):
        evidence, hostname = _url_details(match.group(0))
        domain = _registrable_domain(hostname)
        urls.append((evidence, hostname, domain))
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass
        is_shortener = domain in SHORTENER_DOMAINS
        is_lookalike = _looks_like_brand(hostname)
        if is_ip or is_shortener or is_lookalike or domain not in ALLOWED_DOMAINS:
            reason = "The link does not use a domain in the trusted-site allowlist."
            strong = False
            if is_ip:
                reason = "The link uses a raw IP address instead of a recognizable organization domain."
                strong = True
            elif is_shortener:
                reason = "The shortened link hides its final destination."
                strong = True
            elif is_lookalike:
                reason = "The domain uses digit substitutions that imitate a known brand."
                strong = True
            _add_signal(signals, "suspicious_link", evidence, reason, strong)
            if is_lookalike:
                _add_signal(
                    signals,
                    "unregistered_or_lookalike_domain",
                    evidence,
                    "The address visually imitates a familiar brand without using its official domain.",
                    True,
                )
    return urls


def _detect_payment(text: str, signals: list[Signal]) -> None:
    pattern = (
        rf"(?:{CURRENCY_AMOUNT}.{{0,45}}\b(?:{PAYMENT_WORDS})\b|"
        rf"\b(?:{PAYMENT_WORDS})\b.{{0,45}}{CURRENCY_AMOUNT})"
    )
    for match in re.finditer(pattern, text, re.IGNORECASE | re.UNICODE):
        evidence = match.group(0)
        _add_signal(
            signals,
            "payment_demand",
            evidence,
            "The message connects a specific payment amount with a demand or consequence.",
            True,
        )
        if re.search(
            r"fee|fees|deposit|registration|training|unlock|customs|शुल्क|फीस|shulk",
            evidence,
            re.IGNORECASE,
        ):
            _add_signal(
                signals,
                "fee_before_benefit",
                evidence,
                "An upfront fee is requested before a promised service, job, or release.",
                True,
            )


def _detect_credentials(text: str, signals: list[Signal]) -> None:
    credential = r"OTP|PIN|CVV|password|Aadhaar|PAN|SSN|card number|ओटीपी|पिन|पासवर्ड|आधार|पैन"
    action = r"share|send|provide|verify|confirm|enter|tell(?: us)?|reply with|बताएं|भेजें|साझा करें|वेरिफाई|batao|bhejo|share karo"
    patterns = [
        rf"\b(?:{action})\b.{{0,24}}\b(?:your\s+)?(?:{credential})\b",
        rf"\b(?:{credential})\b.{{0,24}}\b(?:{action})\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.UNICODE):
            evidence = match.group(0)
            if re.search(r"do not share|never share|कभी साझा न|मत बताना", evidence, re.IGNORECASE):
                continue
            _add_signal(
                signals,
                "otp_or_credential_request",
                evidence,
                "Legitimate organizations should not ask you to disclose authentication or identity secrets.",
                True,
            )


def _detect_sender_mismatch(
    text: str,
    urls: list[tuple[str, str, str]],
    signals: list[Signal],
) -> None:
    lower_text = text.casefold()
    present_brands = [brand for brand in BRAND_DOMAINS if brand in lower_text]
    job_context = re.search(r"\b(?:job|career|recruit|selected|hr|work from home)\b", text, re.IGNORECASE)
    for match in EMAIL_PATTERN.finditer(text):
        domain = match.group(0).rsplit("@", 1)[1].lower()
        if domain in FREE_MAIL_DOMAINS and (present_brands or job_context):
            _add_signal(
                signals,
                "sender_mismatch",
                match.group(0),
                "An institutional or recruiting claim is using a free personal email service.",
                True,
            )
    for brand in present_brands:
        expected_domains = BRAND_DOMAINS[brand]
        for evidence, _, domain in urls:
            if domain not in expected_domains:
                _add_signal(
                    signals,
                    "sender_mismatch",
                    evidence,
                    f"The message names {brand.title()} but links to a different domain.",
                    True,
                )


def _detect_other_signals(text: str, signals: list[Signal]) -> None:
    _add_pattern_matches(
        signals,
        text,
        r"\b(?:within 24 hours|immediately|urgent|account will be (?:suspended|blocked)|last warning|final notice|act now|pay now|turant|jaldi|abhi|तुरंत|अभी|जल्दी|24 घंटे)\b",
        "urgency_pressure",
        "The wording pressures the recipient to act before independently checking the claim.",
        True,
    )
    _add_pattern_matches(
        signals,
        text,
        r"\b(?:legal action|arrest|FIR|warrant|account suspension|registration cancellation|vehicle registration will be suspended|face (?:a |an )?(?:₹|Rs\.?|INR|USD|\$)?\s*[\d,]*\s*penalty)\b",
        "threat_of_consequences",
        "The sender uses punishment or official consequences to force compliance.",
        True,
    )
    _add_pattern_matches(
        signals,
        text,
        r"\b(?:lottery|prize|winner|guaranteed returns?|free gift|inaam|इनाम|\d+(?:\.\d+)?%\s+(?:daily|weekly)\s+profit)\b",
        "too_good_to_be_true",
        "The promise is unusually generous or claims returns that legitimate services cannot guarantee.",
        True,
    )

    has_payment = any(signal.flag_type == "payment_demand" for signal in signals)
    has_threat = any(signal.flag_type == "threat_of_consequences" for signal in signals)
    if has_payment or has_threat:
        _add_pattern_matches(
            signals,
            text,
            r"\b(?:police|customs|CBI|court|digital arrest|income tax)\b",
            "unusual_channel",
            "An authority reference is paired with a payment demand or threat in an informal message.",
            True,
        )

    _add_pattern_matches(
        signals,
        text,
        r"\b(?:work from home|per task|telegram\s+(?:HR|recruiter)|HR\s+(?:on|at)\s+telegram)\b",
        "unusual_channel",
        "The recruiting or task-work approach uses a pattern common in advance-fee job scams.",
        False,
    )


FAMILY_PATTERNS = {
    "delivery_smishing": r"\b(?:parcel|delivery|shipment|courier|customs fee|india post|fedex|dhl|usps)\b",
    "toll_or_fine_smishing": r"\b(?:toll|fastag|challan|traffic fine|vehicle registration)\b",
    "bank_or_upi_phishing": r"\b(?:bank|upi|kyc|otp|pin|cvv|card number|aadhaar|pan)\b",
    "job_or_task_scam": r"\b(?:job|work from home|data entry|per task|registration fee|training fee|recruiter|telegram hr|selected for)\b",
    "government_imposter": r"\b(?:digital arrest|police|cbi|court|fir|warrant|income tax|customs)\b",
    "family_emergency_imposter": r"\b(?:mom|dad|son|daughter|relative).{0,30}\b(?:lost my phone|emergency|new number|need money)\b",
    "investment_or_crypto": r"\b(?:crypto|bitcoin|trading group|investment|guaranteed returns?|daily profit|weekly profit)\b",
    "romance_scam": r"\b(?:love|relationship|dating|fianc[eé]).{0,40}\b(?:money|gift card|transfer|emergency)\b",
    "lottery_or_prize": r"\b(?:lottery|prize|winner|free gift|inaam|इनाम)\b",
    "tech_support": r"\b(?:virus detected|tech support|remote access|anydesk|teamviewer)\b",
    "rental_or_deposit_fraud": r"\b(?:rent|rental|landlord|property).{0,35}\b(?:deposit|advance)\b",
    "subscription_or_billing": r"\b(?:subscription|renewal|invoice|norton|mcafee).{0,35}\b(?:pay|refund|charge|renew)\b",
    "sextortion": r"\b(?:intimate|compromising|private (?:photo|video)).{0,45}\b(?:release|publish|pay|blackmail)\b",
    "account_takeover_phishing": r"\b(?:password reset|login attempt|account access|verify your account)\b",
}


def _best_family(text: str, verdict: str) -> str:
    if verdict in {"likely_legitimate", "insufficient_content"}:
        return "not_scam"
    scores = {
        family: len(re.findall(pattern, text, re.IGNORECASE | re.UNICODE))
        for family, pattern in FAMILY_PATTERNS.items()
    }
    if not any(scores.values()):
        return "other_scam"
    if scores["delivery_smishing"] and re.search(r"\b(?:parcel|delivery|shipment|courier)\b", text, re.IGNORECASE):
        scores["delivery_smishing"] += 2
    return max(scores, key=scores.get)


def _detect_language(text: str) -> str:
    if re.search(r"[\u0900-\u097F]", text):
        return "Hindi"
    hinglish_hits = re.findall(r"\b(?:jaldi|turant|bhugtan|shulk|inaam|batao|bhejo|karo)\b", text, re.IGNORECASE)
    return "Hinglish" if len(hinglish_hits) >= 2 else "English"


def _insufficient(headline: str, language: str = "unknown") -> dict[str, Any]:
    return {
        "verdict": "insufficient_content",
        "confidence": 100,
        "scam_family": "not_scam",
        "scam_family_label": FAMILY_LABELS["not_scam"],
        "headline": headline,
        "red_flags": [],
        "what_to_do": FAMILY_ACTIONS["not_scam"],
        "what_scammer_wants": None,
        "message_language": language,
        "engine": "rules",
        "demo_mode": False,
    }


def analyze_rules(
    text: str | None,
    image_bytes: bytes | None = None,
    image_format: str | None = None,
) -> dict[str, Any]:
    if image_bytes is not None:
        return _insufficient(
            "Screenshot analysis needs the AI engine and is coming soon; paste the message text for a rule-based check now."
        )

    message = text or ""
    language = _detect_language(message)
    if len(re.sub(r"[^\w\u0900-\u097F]+", "", message, flags=re.UNICODE)) < 4:
        return _insufficient(
            "There is not enough message content to make a reliable judgment.",
            language,
        )

    signals: list[Signal] = []
    urls = _detect_urls(message, signals)
    _detect_payment(message, signals)
    _detect_credentials(message, signals)
    _detect_other_signals(message, signals)
    _detect_sender_mismatch(message, urls, signals)

    strong_count = sum(signal.strong for signal in signals)
    has_credential_request = any(
        signal.flag_type == "otp_or_credential_request" for signal in signals
    )
    has_threat = any(signal.flag_type == "threat_of_consequences" for signal in signals)
    has_payment = any(signal.flag_type == "payment_demand" for signal in signals)
    has_urgency = any(signal.flag_type == "urgency_pressure" for signal in signals)

    if not signals:
        verdict = "likely_legitimate"
        confidence = 68
    elif strong_count >= 3:
        verdict = "scam"
        confidence = min(97, 91 + strong_count)
    elif (
        len(signals) >= 2
        or (has_payment and has_urgency)
        or has_credential_request
        or has_threat
    ):
        verdict = "likely_scam"
        confidence = min(90, 76 + (strong_count * 3) + len(signals))
    else:
        verdict = "suspicious"
        confidence = 66 if not signals[0].strong else 72

    family = _best_family(message, verdict)
    label = FAMILY_LABELS[family]
    if verdict == "likely_legitimate":
        headline = "No specific scam pattern was found, but use an official channel for any sensitive action."
        scammer_goal = None
    elif verdict == "suspicious":
        headline = f"This message has a warning sign associated with {label.lower()}; verify it independently."
        scammer_goal = "The sender may be trying to obtain money, credentials, or personal information."
    else:
        qualifier = "strongly matches" if verdict == "scam" else "matches"
        headline = f"This message {qualifier} the pattern of a {label.lower()}."
        scammer_goal = "The sender is likely trying to obtain money, credentials, or personal information."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "scam_family": family,
        "scam_family_label": label,
        "headline": headline,
        "red_flags": [
            {
                "type": signal.flag_type,
                "evidence": signal.evidence,
                "explanation": signal.explanation,
            }
            for signal in signals
        ],
        "what_to_do": FAMILY_ACTIONS[family],
        "what_scammer_wants": scammer_goal,
        "message_language": language,
        "engine": "rules",
        "demo_mode": False,
    }
