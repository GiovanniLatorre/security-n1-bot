"""Base playbook with shared AWS helpers and verdict definitions."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

import boto3
import yaml

logger = logging.getLogger(__name__)

CONFIG_PATH = "config/accounts.yaml"


class Verdict(Enum):
    FALSE_POSITIVE = "fp"
    LIKELY_FP = "likely_fp"
    NEEDS_VALIDATION = "validate"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class InvestigationResult:
    verdict: Verdict
    summary: str
    evidence: list[str] = field(default_factory=list)
    user_identified: Optional[str] = None
    domain: Optional[str] = None
    instance_name: Optional[str] = None
    escalation_message: Optional[str] = None


def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def get_account_config(account_name: str) -> Optional[dict]:
    cfg = load_config()
    accounts = cfg.get("accounts", {})

    if account_name in accounts:
        return accounts[account_name]

    for name, acct in accounts.items():
        if acct.get("account_id") == account_name:
            return acct

    return None


class AWSHelper:
    """Thin wrapper around boto3 clients scoped to one AWS account."""

    def __init__(self, account_name: str, region: str = "us-east-1"):
        self.account_config = get_account_config(account_name)
        if not self.account_config:
            raise ValueError(f"Account '{account_name}' not found in config")
        self.profile = self.account_config["profile"]
        self.region = region
        self._session = boto3.Session(profile_name=self.profile, region_name=region)
        self._clients: dict[str, Any] = {}

    def _client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self._session.client(service)
        return self._clients[service]

    # -- GuardDuty --------------------------------------------------------

    def get_guardduty_finding(self, finding_id: str) -> Optional[dict]:
        detector_id = self.account_config.get("guardduty_detector")
        if not detector_id:
            return None
        resp = self._client("guardduty").get_findings(
            DetectorId=detector_id, FindingIds=[finding_id]
        )
        findings = resp.get("Findings", [])
        return findings[0] if findings else None

    def list_findings_for_instance(self, instance_id: str) -> list[dict]:
        detector_id = self.account_config.get("guardduty_detector")
        if not detector_id:
            return []
        gd = self._client("guardduty")
        resp = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "resource.instanceDetails.instanceId": {"Eq": [instance_id]}
                }
            },
            SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
            MaxResults=20,
        )
        finding_ids = resp.get("FindingIds", [])
        if not finding_ids:
            return []
        resp2 = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
        return resp2.get("Findings", [])

    def find_finding_by_instance_and_type(
        self, instance_id: str, finding_type: str
    ) -> Optional[dict]:
        detector_id = self.account_config.get("guardduty_detector")
        if not detector_id:
            return None
        gd = self._client("guardduty")
        resp = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "resource.instanceDetails.instanceId": {"Eq": [instance_id]},
                    "type": {"Eq": [finding_type]},
                }
            },
            SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
            MaxResults=1,
        )
        finding_ids = resp.get("FindingIds", [])
        if not finding_ids:
            return None
        resp2 = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
        findings = resp2.get("Findings", [])
        return findings[0] if findings else None

    # -- EC2 --------------------------------------------------------------

    def describe_instance(self, instance_id: str) -> Optional[dict]:
        try:
            resp = self._client("ec2").describe_instances(InstanceIds=[instance_id])
            reservations = resp.get("Reservations", [])
            if reservations and reservations[0].get("Instances"):
                return reservations[0]["Instances"][0]
        except Exception as exc:
            logger.warning("describe_instance %s failed: %s", instance_id, exc)
        return None

    def get_instance_tags(self, instance: dict) -> dict[str, str]:
        return {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

    def is_vpn_instance(self, instance_id: str) -> bool:
        vpn_list = self.account_config.get("vpn_instances", [])
        if instance_id in vpn_list:
            return True
        instance = self.describe_instance(instance_id)
        if not instance:
            return False
        tags = self.get_instance_tags(instance)
        name = tags.get("Name", "").lower()
        return "pritunl" in name or "vpn" in name

    # -- CloudWatch Logs (Route53 DNS) ------------------------------------

    def query_dns_logs(
        self,
        filter_pattern: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 50,
    ) -> list[dict]:
        log_group = self.account_config.get("dns_log_group")
        if not log_group:
            return []
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        try:
            resp = self._client("logs").filter_log_events(
                logGroupName=log_group,
                startTime=start_ms,
                endTime=end_ms,
                filterPattern=filter_pattern,
                limit=limit,
            )
            results = []
            for event in resp.get("events", []):
                try:
                    results.append(json.loads(event["message"]))
                except json.JSONDecodeError:
                    results.append({"raw": event["message"]})
            return results
        except Exception as exc:
            logger.warning("query_dns_logs failed: %s", exc)
            return []

    def find_dns_query_source(
        self, domain: str, event_time: datetime, window_minutes: int = 10
    ) -> list[dict]:
        start = event_time - timedelta(minutes=window_minutes)
        end = event_time + timedelta(minutes=window_minutes)
        return self.query_dns_logs(domain, start, end)

    def get_dns_context_for_ip(
        self, src_ip: str, event_time: datetime, window_minutes: int = 10, limit: int = 50
    ) -> list[dict]:
        start = event_time - timedelta(minutes=window_minutes)
        end = event_time + timedelta(minutes=window_minutes)
        return self.query_dns_logs(src_ip, start, end, limit=limit)

    # -- SSM (read-only grep on instances) --------------------------------

    def ssm_grep(
        self, instance_id: str, pattern: str, log_path: str = "/var/log/pritunl*"
    ) -> Optional[str]:
        try:
            ssm = self._client("ssm")
            cmd = f'grep -r "{pattern}" {log_path} 2>/dev/null | grep user_connect | tail -5'
            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
            )
            command_id = resp["Command"]["CommandId"]
            for _ in range(10):
                time.sleep(3)
                result = ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
                if result["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                    break
            if result["Status"] == "Success":
                return result.get("StandardOutputContent", "")
            logger.warning("SSM command %s status: %s", command_id, result["Status"])
            return None
        except Exception as exc:
            logger.warning("ssm_grep on %s failed: %s", instance_id, exc)
            return None

    def identify_vpn_user(self, instance_id: str, client_ip: str) -> Optional[dict]:
        output = self.ssm_grep(instance_id, client_ip)
        if not output or not output.strip():
            subnet = ".".join(client_ip.split(".")[:3])
            output = self.ssm_grep(instance_id, subnet)
            if not output or not output.strip():
                return None

        for line in output.strip().split("\n"):
            if client_ip not in line:
                continue
            try:
                json_start = line.index("{")
                data = json.loads(line[json_start:])
                return {
                    "user_name": data.get("user_name"),
                    "user_email": data.get("user_email", data.get("user_name")),
                    "platform": data.get("platform"),
                    "device_name": data.get("device_name"),
                    "mac_addr": data.get("mac_addr"),
                    "real_address": data.get("real_address"),
                    "virt_address": data.get("virt_address"),
                    "server_name": data.get("server_name"),
                }
            except (json.JSONDecodeError, ValueError):
                continue

        return None

    # -- CloudTrail -------------------------------------------------------

    def lookup_cloudtrail_events(
        self,
        attribute_key: str,
        attribute_value: str,
        start_time: datetime,
        end_time: datetime,
        max_results: int = 20,
    ) -> list[dict]:
        try:
            resp = self._client("cloudtrail").lookup_events(
                LookupAttributes=[
                    {"AttributeKey": attribute_key, "AttributeValue": attribute_value}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=max_results,
            )
            results = []
            for event in resp.get("Events", []):
                detail = json.loads(event.get("CloudTrailEvent", "{}"))
                results.append(
                    {
                        "time": str(event.get("EventTime", "")),
                        "name": event.get("EventName", ""),
                        "username": event.get("Username", ""),
                        "source_ip": detail.get("sourceIPAddress", ""),
                        "user_agent": detail.get("userAgent", ""),
                        "user_arn": detail.get("userIdentity", {}).get("arn", ""),
                        "error": detail.get("errorCode", ""),
                        "request": detail.get("requestParameters", {}),
                    }
                )
            return results
        except Exception as exc:
            logger.warning("CloudTrail lookup failed: %s", exc)
            return []
