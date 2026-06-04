"""Slack reporter: formats investigation results and posts to thread."""

from __future__ import annotations

import logging
from typing import Optional

from slack_sdk import WebClient

from playbooks.base import InvestigationResult, Verdict, load_config

logger = logging.getLogger(__name__)

VERDICT_EMOJI = {
    Verdict.FALSE_POSITIVE: ":white_check_mark:",
    Verdict.LIKELY_FP: ":large_yellow_circle:",
    Verdict.NEEDS_VALIDATION: ":warning:",
    Verdict.CRITICAL: ":rotating_light:",
    Verdict.UNKNOWN: ":question:",
}

VERDICT_LABEL = {
    Verdict.FALSE_POSITIVE: "Falso Positivo",
    Verdict.LIKELY_FP: "Probable Falso Positivo",
    Verdict.NEEDS_VALIDATION: "Requiere Validación",
    Verdict.CRITICAL: "CRÍTICO - Acción Requerida",
    Verdict.UNKNOWN: "No Determinado - Requiere Análisis Manual",
}


def format_message(result: InvestigationResult) -> str:
    emoji = VERDICT_EMOJI.get(result.verdict, ":question:")
    label = VERDICT_LABEL.get(result.verdict, "Desconocido")

    lines = [
        f"{emoji} *Clasificación: {label}*",
        "",
        result.summary,
    ]

    if result.evidence:
        lines.append("")
        lines.append("*Evidencias recopiladas:*")
        for ev in result.evidence:
            lines.append(f"• {ev}")

    return "\n".join(lines)


def _build_escalation_message(
    result: InvestigationResult, escalation_user: str
) -> str:
    emoji = VERDICT_EMOJI.get(result.verdict, ":warning:")
    label = VERDICT_LABEL.get(result.verdict, "Requiere Atención")

    lines = [
        f"{emoji} *{label}* — <@{escalation_user}>",
        "",
        result.summary,
    ]

    if result.escalation_message:
        lines.append("")
        lines.append(result.escalation_message)

    if result.evidence:
        lines.append("")
        lines.append("*Contexto recopilado:*")
        for ev in result.evidence[:5]:
            lines.append(f"• {ev}")

    return "\n".join(lines)


class SlackReporter:
    def __init__(self, bot_token: str):
        self.client = WebClient(token=bot_token)
        self._config = load_config()
        self._escalation_user = self._config.get("escalation_user", "")

    def post_result(
        self,
        channel: str,
        thread_ts: str,
        result: InvestigationResult,
    ) -> Optional[str]:
        needs_escalation = result.verdict in (
            Verdict.NEEDS_VALIDATION,
            Verdict.CRITICAL,
            Verdict.UNKNOWN,
        )

        if needs_escalation:
            text = _build_escalation_message(result, self._escalation_user)
        else:
            text = format_message(result)

        try:
            resp = self.client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text=text,
                unfurl_links=False,
                unfurl_media=False,
            )
            ts = resp.get("ts")
            logger.info(
                "Posted %s result to %s (thread %s): %s",
                result.verdict.value,
                channel,
                thread_ts,
                ts,
            )

            if not needs_escalation:
                try:
                    self.client.reactions_add(
                        channel=channel,
                        timestamp=thread_ts,
                        name="white_check_mark",
                    )
                except Exception:
                    pass

            return ts
        except Exception as exc:
            logger.error("Failed to post to Slack: %s", exc)
            return None
