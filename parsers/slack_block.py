"""Parser for Splunk alert blocks arriving in Slack."""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

FIELD_PATTERNS = {
    "aws_resource_id": re.compile(r"aws_resource_id[:\s]+([a-z0-9\-]+)", re.IGNORECASE),
    "aws_region": re.compile(r"aws_region[:\s]+([\w\-]+)", re.IGNORECASE),
    "aws_account": re.compile(r"aws_account[:\s]+(\w+)", re.IGNORECASE),
    "aws_account_id": re.compile(r"aws_account_id[:\s]+(\d+)", re.IGNORECASE),
    "hostname": re.compile(r"hostname[:\s]+([a-z0-9\-]+)", re.IGNORECASE),
    "k8s_cluster": re.compile(r"k8s_cluster[:\s]+(\S+)", re.IGNORECASE),
    "k8s_namespace": re.compile(r"k8s_namespace[:\s]+(\S+)", re.IGNORECASE),
}

GUARDDUTY_TYPE_RE = re.compile(
    r"((?:Trojan|CryptoCurrency|Impact|DefenseEvasion|AttackSequence|Recon|UnauthorizedAccess)"
    r":[A-Za-z0-9/!.]+)",
)

ALERT_TITLE_PATTERNS = [
    re.compile(r"AWS GuardDuty\s+(.+?)\s+finding\s+in", re.IGNORECASE),
    re.compile(r"(Modification on AWS .+?)(?:\n|$)", re.IGNORECASE),
    re.compile(r"(Kubernetes pod issue detected)", re.IGNORECASE),
]


@dataclass
class Alert:
    alert_type: str
    instance_id: Optional[str] = None
    region: str = "us-east-1"
    account_name: Optional[str] = None
    account_id: Optional[str] = None
    k8s_cluster: Optional[str] = None
    k8s_namespace: Optional[str] = None
    severity: Optional[float] = None
    raw_message: str = ""
    slack_channel: str = ""
    slack_thread_ts: str = ""
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


def _extract_text_from_blocks(payload: dict) -> str:
    """Flatten Slack blocks/attachments into searchable text."""
    parts: list[str] = []

    for att in payload.get("attachments", []):
        parts.append(att.get("text", ""))
        parts.append(att.get("fallback", ""))
        parts.append(att.get("pretext", ""))
        for f in att.get("fields", []):
            parts.append(f"{f.get('title', '')}: {f.get('value', '')}")

    for block in payload.get("blocks", []):
        if block.get("type") == "section":
            txt = block.get("text", {})
            parts.append(txt.get("text", ""))
            for f in block.get("fields", []):
                parts.append(f.get("text", ""))
        elif block.get("type") == "rich_text":
            for elem in block.get("elements", []):
                for sub in elem.get("elements", []):
                    parts.append(sub.get("text", ""))

    if "text" in payload and isinstance(payload["text"], str):
        parts.append(payload["text"])

    return "\n".join(p for p in parts if p)


def _extract_field(text: str, name: str) -> Optional[str]:
    pattern = FIELD_PATTERNS.get(name)
    if not pattern:
        return None
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _extract_alert_type(text: str) -> str:
    gd_match = GUARDDUTY_TYPE_RE.search(text)
    if gd_match:
        return gd_match.group(1)

    for pattern in ALERT_TITLE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(1).strip()

    first_line = text.strip().split("\n")[0][:120]
    return first_line


def parse_slack_message(event: dict) -> Optional[Alert]:
    """Parse a Slack message event into a structured Alert."""
    text = _extract_text_from_blocks(event)
    if not text:
        plain = event.get("text", "")
        if not plain:
            return None
        text = plain

    alert_type = _extract_alert_type(text)
    if not alert_type:
        return None

    instance_id = (
        _extract_field(text, "aws_resource_id")
        or _extract_field(text, "hostname")
    )
    region = _extract_field(text, "aws_region") or "us-east-1"
    account_name = _extract_field(text, "aws_account")
    account_id = _extract_field(text, "aws_account_id")
    k8s_cluster = _extract_field(text, "k8s_cluster")
    k8s_namespace = _extract_field(text, "k8s_namespace")

    domain_matches = re.findall(r"https?://([a-zA-Z0-9._\-]+)", text)
    url_matches = re.findall(r"(https?://[^\s,]+)", text)

    return Alert(
        alert_type=alert_type,
        instance_id=instance_id,
        region=region,
        account_name=account_name,
        account_id=account_id,
        k8s_cluster=k8s_cluster,
        k8s_namespace=k8s_namespace,
        raw_message=text,
        slack_channel=event.get("channel", ""),
        slack_thread_ts=event.get("ts", ""),
        domains=domain_matches,
        urls=url_matches,
    )
