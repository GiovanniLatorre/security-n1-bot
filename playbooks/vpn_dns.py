"""Playbook: GuardDuty DNS findings on VPN Pritunl instances.

Replicates the manual forensic investigation:
1. Get finding details (domain, timestamps)
2. Confirm instance is a VPN server
3. Query Route53 DNS logs to find the real source IP
4. If source != server IP, it's a VPN client
5. Identify the VPN user via Pritunl logs (SSM)
6. Collect DNS context to confirm normal browsing
7. Verdict: FP if traffic originated from a VPN client
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from parsers.slack_block import Alert
from playbooks.base import (
    AWSHelper,
    InvestigationResult,
    Verdict,
)

logger = logging.getLogger(__name__)

KNOWN_AD_NETWORKS = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "pubmatic.com", "casalemedia.com", "rubiconproject.com",
    "adnxs.com", "smartadserver.com", "seedtag.com", "onetag-sys.com",
    "e-planning.net", "viralize.tv", "pinterest.com", "snapchat.com",
}

LEGITIMATE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "slack.com", "slackb.com",
    "whatsapp.com", "facebook.com", "spotify.com", "apple.com",
    "microsoft.com", "github.com", "atlassian.net", "cursor.sh",
    "trendmicro.com", "jumpcloud.com", "datadog.com", "sentry.io",
    "amazonaws.com", "example-corp.com",
}


def _is_normal_browsing(dns_queries: list[dict]) -> bool:
    """Heuristic: if most DNS queries are to known-legitimate domains, it's normal."""
    if not dns_queries:
        return False
    legitimate_count = 0
    for q in dns_queries:
        qname = q.get("query_name", "").rstrip(".")
        for dom in LEGITIMATE_DOMAINS:
            if qname.endswith(dom):
                legitimate_count += 1
                break
    ratio = legitimate_count / len(dns_queries)
    return ratio > 0.3


def _extract_finding_domain(finding: dict) -> str | None:
    action = finding.get("Service", {}).get("Action", {})
    dns_action = action.get("DnsRequestAction", {})
    return dns_action.get("Domain")


def _extract_finding_time(finding: dict) -> datetime:
    first_seen = finding.get("Service", {}).get("EventFirstSeen", "")
    return datetime.fromisoformat(first_seen.replace("Z", "+00:00"))


def _extract_threat_list(finding: dict) -> str:
    evidence = finding.get("Service", {}).get("Evidence", {})
    details = evidence.get("ThreatIntelligenceDetails", [])
    if details:
        return details[0].get("ThreatListName", "N/A")
    return "N/A"


def investigate(alert: Alert) -> InvestigationResult:
    aws = AWSHelper(alert.account_name, alert.region)
    evidence: list[str] = []

    # Step 1: Confirm this is a VPN instance
    instance = aws.describe_instance(alert.instance_id)
    if not instance:
        return InvestigationResult(
            verdict=Verdict.UNKNOWN,
            summary=f"La instancia {alert.instance_id} no fue encontrada (posiblemente terminada).",
            evidence=["Instance not found via EC2 API"],
        )

    tags = aws.get_instance_tags(instance)
    instance_name = tags.get("Name", "unknown")
    private_ip = instance.get("PrivateIpAddress", "")
    source_dest_check = instance.get("SourceDestCheck", True)

    if not aws.is_vpn_instance(alert.instance_id):
        return InvestigationResult(
            verdict=Verdict.UNKNOWN,
            summary=(
                f"La instancia {alert.instance_id} ({instance_name}) no es una instancia VPN conocida. "
                "Requiere investigación manual."
            ),
            evidence=[f"Instance name: {instance_name}", f"SourceDestCheck: {source_dest_check}"],
        )

    evidence.append(f"Instancia confirmada como VPN: {instance_name} (IP: {private_ip}, SourceDestCheck: {source_dest_check})")

    # Step 2: Get the GuardDuty finding
    finding = aws.find_finding_by_instance_and_type(alert.instance_id, alert.alert_type)

    if not finding:
        findings = aws.list_findings_for_instance(alert.instance_id)
        if findings:
            finding = findings[0]

    if not finding:
        return InvestigationResult(
            verdict=Verdict.UNKNOWN,
            summary=f"No se encontró el finding de GuardDuty para {alert.instance_id}.",
            evidence=evidence,
            instance_name=instance_name,
        )

    domain = _extract_finding_domain(finding)
    event_time = _extract_finding_time(finding)
    threat_list = _extract_threat_list(finding)
    count = finding.get("Service", {}).get("Count", 0)

    evidence.append(f"Dominio: {domain} | Threat feed: {threat_list} | Count: {count}")

    # Step 3: Query Route53 DNS logs
    dns_results = aws.find_dns_query_source(domain, event_time, window_minutes=10)

    if not dns_results:
        return InvestigationResult(
            verdict=Verdict.LIKELY_FP,
            summary=(
                f"La instancia {alert.instance_id} ({instance_name}) es el servidor VPN Pritunl. "
                f"El dominio `{domain}` está flaggeado por {threat_list}. "
                "No se encontraron DNS query logs para confirmar el origen, "
                "pero el patrón es consistente con tráfico de clientes VPN."
            ),
            evidence=evidence,
            domain=domain,
            instance_name=instance_name,
        )

    # Step 4: Check if queries came from VPN clients (not the server)
    client_queries: list[dict] = []
    for q in dns_results:
        src_addr = q.get("srcaddr", "")
        if src_addr and src_addr != private_ip:
            client_queries.append(q)

    if not client_queries:
        return InvestigationResult(
            verdict=Verdict.NEEDS_VALIDATION,
            summary=(
                f"Las consultas DNS a `{domain}` se originaron desde el propio servidor VPN "
                f"({private_ip}), no desde clientes. Requiere investigación adicional."
            ),
            evidence=evidence,
            domain=domain,
            instance_name=instance_name,
        )

    evidence.append(
        f"{len(client_queries)} consulta(s) DNS originada(s) desde clientes VPN, no desde el servidor"
    )

    # Step 5: Identify VPN users
    users_identified: list[str] = []
    src_ips = list({q.get("srcaddr") for q in client_queries})

    for src_ip in src_ips[:3]:
        user_info = aws.identify_vpn_user(alert.instance_id, src_ip)
        if user_info and user_info.get("user_name"):
            user_desc = (
                f"`{user_info['user_name']}` "
                f"(perfil VPN: {user_info.get('server_name', 'N/A')}, "
                f"plataforma: {user_info.get('platform', 'N/A')})"
            )
            users_identified.append(user_desc)
            evidence.append(f"Usuario identificado para {src_ip}: {user_info['user_name']}")
        else:
            evidence.append(
                f"No fue posible identificar el usuario para {src_ip} (log rotado)"
            )

    # Step 6: Get DNS context
    context_results = aws.get_dns_context_for_ip(
        src_ips[0], event_time, window_minutes=10, limit=50
    )
    normal_browsing = _is_normal_browsing(context_results)

    if normal_browsing:
        evidence.append("Contexto DNS muestra navegación legítima (Google, Slack, etc.)")
    else:
        evidence.append("Contexto DNS no muestra un patrón claro de navegación normal")

    # Step 7: Build verdict
    if users_identified and normal_browsing:
        users_text = ", ".join(users_identified)
        summary = (
            f"La instancia `{alert.instance_id}` es el servidor VPN Pritunl (`{instance_name}`). "
            f"La(s) consulta(s) DNS a `{domain}` fue(ron) realizada(s) por {users_text} "
            f"mientras navegaban sitios legítimos. "
            f"El dominio está flaggeado por el threat feed de {threat_list}. "
            f"Datos confirmados vía DNS query logs de Route53 y logs de Pritunl vía SSM."
        )
        return InvestigationResult(
            verdict=Verdict.FALSE_POSITIVE,
            summary=summary,
            evidence=evidence,
            user_identified=", ".join(u.split("`")[1] for u in users_identified if "`" in u),
            domain=domain,
            instance_name=instance_name,
        )

    if client_queries and not users_identified:
        summary = (
            f"La instancia `{alert.instance_id}` es el servidor VPN Pritunl (`{instance_name}`). "
            f"Las consultas DNS a `{domain}` se originaron desde clientes VPN "
            f"(IP(s): {', '.join(src_ips[:3])}), no desde el servidor. "
            f"El dominio está flaggeado por {threat_list}. "
            f"No fue posible identificar al usuario específico (log de Pritunl rotado)."
        )
        return InvestigationResult(
            verdict=Verdict.LIKELY_FP,
            summary=summary,
            evidence=evidence,
            domain=domain,
            instance_name=instance_name,
        )

    return InvestigationResult(
        verdict=Verdict.NEEDS_VALIDATION,
        summary=(
            f"La instancia `{alert.instance_id}` ({instance_name}) generó consultas DNS a `{domain}`. "
            "Se necesita validación manual."
        ),
        evidence=evidence,
        domain=domain,
        instance_name=instance_name,
    )
