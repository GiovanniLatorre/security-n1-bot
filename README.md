# Security N1 Bot

> Slack bot with playbooks for tier-1 security alert triage (VPN/DNS, Databricks ephemeral, etc.).

| | |
|---|---|
| **Stack** | Python 3, Slack API, Docker |
| **Visibility** | Public |
| **Type** | ChatOps / alert automation |

## Overview

Slack-integrated bot that parses alert blocks and runs predefined playbooks against AWS and internal APIs. Designed to accelerate N1 investigations with consistent steps and Slack-formatted responses.

## Features

- **Playbooks** — VPN/DNS, Databricks ephemeral nodes (`playbooks/`)
- **Slack parsing** — block kit parser (`parsers/slack_block.py`)
- **Reporting** — formatted replies (`reporters/slack.py`)
- **Docker** — containerized deployment

## Prerequisites

- Python 3.11+
- Slack bot token and signing secret
- AWS SSO profiles matching `config/accounts.yaml` (local)

## Quick start

```bash
cp .env.example .env
cp config/accounts.yaml.example config/accounts.yaml

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 bot.py
```

Docker:

```bash
docker build -t security-n1-bot .
docker run --env-file .env security-n1-bot
```

## Configuration

| File | Purpose |
|------|---------|
| `.env` | Slack tokens (gitignored) |
| `config/accounts.yaml` | AWS account map (gitignored) |
| `config/playbooks.yaml` | Playbook metadata |

## Project layout

```
security-n1-bot/
├── bot.py
├── playbooks/
├── parsers/
├── reporters/
├── config/
└── Dockerfile
```

## Security & data handling

- Never commit Slack tokens or `accounts.yaml`.
- Bot may query production — scope IAM read-only where possible.

## Related projects

- [security-mcp](https://github.com/GiovanniLatorre/security-mcp)
- [giovanni-portfolio](https://github.com/GiovanniLatorre/giovanni-portfolio)

## License

MIT License — see [LICENSE](LICENSE).
