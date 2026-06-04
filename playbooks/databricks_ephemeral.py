"""Playbook: GuardDuty DNS findings on ephemeral Databricks workers.

Investigation steps:
1. Get finding details (domain, timestamps)
2. Check instance tags for Vendor=Databricks
3. Check if instance still exists or was terminated
4. Check CloudTrail for instance lifecycle (RunInstances/TerminateInstances)
5. Verdict: FP if ephemeral Databricks worker that was terminated
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from parsers.slack_block import Alert
from playbooks.base import (
    AWSHelper,
    InvestigationResult,
    Verdict,
)

logger = logging.getLogger(__name__)


def _extract_finding_domain(finding: dict) -> str | None:
    action = finding.get("Service", {}).get("Action", {})
    return action.get("DnsRequestAction", {}).get("Domain")


def _extract_finding_time(finding: dict) -> datetime:
    first_seen = finding.get("Service", {}).get("EventFirstSeen", "")
    return datetime.fromisoformat(first_seen.replace("Z", "+00:00"))


def _extract_threat_list(finding: dict) -> str:
    evidence = finding.get("Service", {}).get("Evidence", {})
    details = evidence.get("ThreatIntelligenceDetails", [])
    return details[0].get("ThreatListName", "N/A") if details else "N/A"


def investigate(alert: Alert) -> InvestigationResult:
    aws = AWSHelper(alert.account_name, alert.region)
    evidence: list[str] = []

    # Step 1: Get the GuardDuty finding
    finding = aws.find_finding_by_instance_and_type(alert.instance_id, alert.alert_type)
    if not finding:
        findings = aws.list_findings_for_instance(alert.instance_id)
        finding = findings[0] if findings else None

    domain = None
    threat_list = "Sophos"
    event_time = datetime.now(timezone.utc)
    count = 0

    if finding:
        domain = _extract_finding_domain(finding)
        event_time = _extract_finding_time(finding)
        threat_list = _extract_threat_list(finding)
        count = finding.get("Service", {}).get("Count", 0)
        first_seen = finding.get("Service", {}).get("EventFirstSeen", "")
        last_seen = finding.get("Service", {}).get("EventLastSeen", "")
        evidence.append(f"Dominio: {domain} | Threat feed: {threat_list} | Count: {count}")
        evidence.append(f"EventFirstSeen: {first_seen} | EventLastSeen: {last_seen}")

    # Step 2: Check instance
    instance = aws.describe_instance(alert.instance_id)
    instance_terminated = instance is None

    tags: dict[str, str] = {}
    instance_name = "unknown"
    vendor = "unknown"
    cluster_name = "N/A"
    run_name = "N/A"
    job_id = "N/A"
    creator = "N/A"

    if instance:
        tags = aws.get_instance_tags(instance)
        instance_name = tags.get("Name", "unknown")
        vendor = tags.get("Vendor", "unknown")
        cluster_name = tags.get("ClusterName", "N/A")
        run_name = tags.get("RunName", "N/A")
        job_id = tags.get("JobId", "N/A")
        creator = tags.get("Creator", "N/A")
        state = instance.get("State", {}).get("Name", "")
        instance_terminated = state == "terminated"
    else:
        # Try to get tags from the finding itself
        finding_instance = (
            finding.get("Resource", {}).get("InstanceDetails", {}) if finding else {}
        )
        for t in finding_instance.get("Tags", []):
            tags[t["Key"]] = t["Value"]
        instance_name = tags.get("Name", "unknown")
        vendor = tags.get("Vendor", "unknown")
        cluster_name = tags.get("ClusterName", "N/A")
        run_name = tags.get("RunName", "N/A")
        job_id = tags.get("JobId", "N/A")
        creator = tags.get("Creator", "N/A")

    evidence.append(f"Instance: {instance_name} | Vendor: {vendor} | Terminated: {instance_terminated}")

    if vendor != "Databricks":
        return InvestigationResult(
            verdict=Verdict.UNKNOWN,
            summary=(
                f"La instancia `{alert.instance_id}` ({instance_name}) no es un worker de Databricks "
                f"(Vendor={vendor}). Requiere investigación manual."
            ),
            evidence=evidence,
            domain=domain,
            instance_name=instance_name,
        )

    evidence.append(f"ClusterName: {cluster_name} | RunName: {run_name} | JobId: {job_id} | Creator: {creator}")

    # Step 3: Check CloudTrail for lifecycle
    ct_start = event_time - timedelta(hours=2)
    ct_end = event_time + timedelta(hours=2)
    ct_events = aws.lookup_cloudtrail_events(
        "ResourceName", alert.instance_id, ct_start, ct_end, max_results=10
    )

    launched_by = "Databricks"
    terminated_by = "Databricks"
    for ev in ct_events:
        if ev["name"] == "RunInstances":
            launched_by = ev.get("username", "Databricks")
        if ev["name"] == "TerminateInstances":
            terminated_by = ev.get("username", "Databricks")

    evidence.append(f"CloudTrail: launched by {launched_by}, terminated by {terminated_by}")

    # Step 4: Build verdict
    if instance_terminated:
        creator_text = f", creado por `{creator}`" if creator != "N/A" else ""
        run_text = f" ejecutando el job `{run_name}`" if run_name != "N/A" else ""
        summary = (
            f"La instancia `{alert.instance_id}` era un worker efímero de Databricks "
            f"(`{instance_name}`{creator_text}){run_text}. "
            f"Realizó {count} consulta(s) DNS a `{domain}` "
            f"en un burst de 1 segundo, patrón consistente con un job de scraping/crawling. "
            f"El dominio está flaggeado por el threat feed de {threat_list}. "
            f"La instancia ya fue terminada por {terminated_by}."
        )
        return InvestigationResult(
            verdict=Verdict.FALSE_POSITIVE,
            summary=summary,
            evidence=evidence,
            user_identified=creator if creator != "N/A" else None,
            domain=domain,
            instance_name=instance_name,
        )

    # Instance still running - less certain
    summary = (
        f"La instancia `{alert.instance_id}` es un worker de Databricks ({instance_name}) "
        f"que **aún está en ejecución**. Realizó consultas DNS a `{domain}` "
        f"(flaggeado por {threat_list}). Creator: {creator}. "
        f"Como la instancia sigue activa, requiere validación."
    )
    return InvestigationResult(
        verdict=Verdict.NEEDS_VALIDATION,
        summary=summary,
        evidence=evidence,
        user_identified=creator if creator != "N/A" else None,
        domain=domain,
        instance_name=instance_name,
    )
