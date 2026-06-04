"""Security N1 Bot — automated Level 1 security analyst.

Listens to a Slack channel for Splunk alerts, investigates them
using deterministic playbooks, and posts the verdict back as a thread reply.
Only escalates to a human when the finding is critical or uncertain.
"""

from __future__ import annotations

import logging
import os
import sys
import threading

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from parsers.slack_block import Alert, parse_slack_message
from playbooks.base import AWSHelper, InvestigationResult, Verdict, load_config
from playbooks import vpn_dns, databricks_ephemeral
from reporters.slack import SlackReporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("n1-bot")

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN", "")
ALERT_CHANNEL_ID = os.environ.get("ALERT_CHANNEL_ID", "")
BOT_USER_ID: str | None = None

app = App(token=SLACK_BOT_TOKEN)
reporter = SlackReporter(SLACK_BOT_TOKEN)


# -- Playbook routing ----------------------------------------------------

def _is_guardduty_dns(alert_type: str) -> bool:
    dns_types = [
        "DriveBySourceTraffic",
        "PhishingDomainRequest",
        "DNSDataExfiltration",
        "BitcoinTool",
        "AttackSequence",
        "CompromisedInstanceGroup",
    ]
    return any(t in alert_type for t in dns_types)


def _is_cloudtrail_action(alert_type: str) -> bool:
    return any(
        kw in alert_type
        for kw in ("BackupVault", "DeleteRecoveryPoint", "Modification on AWS")
    )


def _is_k8s_issue(alert_type: str) -> bool:
    return any(
        kw in alert_type.lower()
        for kw in ("kubernetes", "pod issue", "imagepullbackoff", "crashloopbackoff")
    )


def route_alert(alert: Alert) -> InvestigationResult:
    """Route an alert to the appropriate playbook based on type and context."""
    logger.info(
        "Routing alert: type=%s instance=%s account=%s",
        alert.alert_type,
        alert.instance_id,
        alert.account_name,
    )

    if not alert.account_name:
        return InvestigationResult(
            verdict=Verdict.UNKNOWN,
            summary="No se pudo determinar la cuenta AWS del alerta. Requiere análisis manual.",
            evidence=[f"Alert type: {alert.alert_type}"],
        )

    if _is_guardduty_dns(alert.alert_type) and alert.instance_id:
        try:
            aws = AWSHelper(alert.account_name, alert.region)

            if aws.is_vpn_instance(alert.instance_id):
                logger.info("Routed to playbook: vpn_dns")
                return vpn_dns.investigate(alert)

            instance = aws.describe_instance(alert.instance_id)
            if instance:
                tags = aws.get_instance_tags(instance)
                if tags.get("Vendor") == "Databricks":
                    logger.info("Routed to playbook: databricks_ephemeral")
                    return databricks_ephemeral.investigate(alert)
            else:
                finding = aws.find_finding_by_instance_and_type(
                    alert.instance_id, alert.alert_type
                )
                if finding:
                    finding_tags = {
                        t["Key"]: t["Value"]
                        for t in finding.get("Resource", {})
                        .get("InstanceDetails", {})
                        .get("Tags", [])
                    }
                    if finding_tags.get("Vendor") == "Databricks":
                        logger.info("Routed to playbook: databricks_ephemeral (from finding tags)")
                        return databricks_ephemeral.investigate(alert)

        except Exception as exc:
            logger.error("Playbook execution failed: %s", exc, exc_info=True)
            return InvestigationResult(
                verdict=Verdict.UNKNOWN,
                summary=f"Error durante la investigación: {exc}",
                evidence=[f"Alert type: {alert.alert_type}", f"Instance: {alert.instance_id}"],
            )

    if _is_cloudtrail_action(alert.alert_type):
        return InvestigationResult(
            verdict=Verdict.NEEDS_VALIDATION,
            summary=(
                f"Acción detectada: `{alert.alert_type}` en la cuenta {alert.account_name}. "
                "Las acciones destructivas siempre requieren validación humana."
            ),
            evidence=[f"Instance: {alert.instance_id}"],
        )

    if _is_k8s_issue(alert.alert_type):
        return InvestigationResult(
            verdict=Verdict.NEEDS_VALIDATION,
            summary=(
                f"Issue de Kubernetes detectado: `{alert.alert_type}` "
                f"en cluster {alert.k8s_cluster or 'desconocido'}, "
                f"namespace {alert.k8s_namespace or 'desconocido'}. "
                "Requiere validación del estado actual de los pods."
            ),
            evidence=[],
        )

    return InvestigationResult(
        verdict=Verdict.UNKNOWN,
        summary=(
            f"Tipo de alerta no reconocido: `{alert.alert_type}`. "
            "No hay playbook disponible. Requiere análisis manual."
        ),
        evidence=[
            f"Instance: {alert.instance_id}",
            f"Account: {alert.account_name}",
            f"Region: {alert.region}",
        ],
    )


# -- Slack event handlers ------------------------------------------------

def _should_process(event: dict) -> bool:
    """Only process messages from bots/apps in the alert channel (Splunk)."""
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return True
    if event.get("user") == BOT_USER_ID:
        return False
    return "aws_resource_id" in event.get("text", "") or "GuardDuty" in event.get("text", "")


def _process_alert_async(event: dict):
    """Run investigation in a background thread to avoid blocking Slack."""
    try:
        alert = parse_slack_message(event)
        if not alert:
            logger.debug("Could not parse alert from message")
            return

        alert.slack_channel = event.get("channel", ALERT_CHANNEL_ID)
        alert.slack_thread_ts = event.get("ts", "")

        logger.info("Investigating: %s on %s (%s)", alert.alert_type, alert.instance_id, alert.account_name)
        result = route_alert(alert)

        reporter.post_result(
            channel=alert.slack_channel,
            thread_ts=alert.slack_thread_ts,
            result=result,
        )
    except Exception as exc:
        logger.error("Unhandled error processing alert: %s", exc, exc_info=True)


@app.event("message")
def handle_message(event, say):
    if event.get("thread_ts"):
        return
    if not _should_process(event):
        return

    logger.info("New alert detected in channel %s", event.get("channel"))
    thread = threading.Thread(target=_process_alert_async, args=(event,), daemon=True)
    thread.start()


@app.event("app_mention")
def handle_mention(event, say):
    say(
        text=(
            "Soy el bot N1 de Cybersecurity. Monitoreo este canal automáticamente "
            "e investigo los alertas de GuardDuty/Splunk. "
            "No necesitas mencionarme — trabajo solo. :robot_face:"
        ),
        thread_ts=event.get("ts"),
    )


# -- Entrypoint ----------------------------------------------------------

def main():
    global BOT_USER_ID

    if not SLACK_BOT_TOKEN:
        logger.error("SLACK_BOT_TOKEN not set")
        sys.exit(1)
    if not SLACK_APP_TOKEN:
        logger.error("SLACK_APP_TOKEN not set")
        sys.exit(1)

    try:
        auth = app.client.auth_test()
        BOT_USER_ID = auth.get("user_id")
        logger.info("Bot authenticated as %s (%s)", auth.get("user"), BOT_USER_ID)
    except Exception as exc:
        logger.error("Slack auth failed: %s", exc)
        sys.exit(1)

    logger.info("N1 Security Bot starting in Socket Mode...")
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()


if __name__ == "__main__":
    main()
