# Agent Gateway

## Google Drive MCP

The selected Drive integration is Google's hosted Drive MCP service. Its endpoint is configurable with `DRIVE_MCP_URL` and gated by `DRIVE_MCP_ENABLED` (off by default). `Settings.active_drive_mcp_url` returns the endpoint only when enabled, so the provider can be switched or disabled without changing callers.

This repository is currently a scaffold: it does not yet contain an MCP client or an agent tool-execution path. These settings establish the provider and feature-flag boundary; enabling the flag alone does not connect to Drive or expose Drive tools.

Before connecting an MCP-capable host:

1. Join the [Google Workspace Developer Preview Program](https://developers.google.com/workspace/preview) and enable both the Google Drive API and Google Drive MCP API in the Google Cloud project.
2. Configure the Google OAuth consent screen and request the Drive MCP scopes `https://www.googleapis.com/auth/drive.readonly` and `https://www.googleapis.com/auth/drive.file`.
3. Configure OAuth in the MCP host and authenticate the user. Do not put OAuth client secrets or access tokens in source control.
4. Set `DRIVE_MCP_ENABLED=true` and, if needed, override `DRIVE_MCP_URL`.

The service is in Developer Preview; availability, behavior, and terms may change. Drive content is untrusted input and can contain indirect prompt-injection instructions. Review Google's [Drive MCP setup guide](https://developers.google.com/workspace/drive/api/guides/configure-mcp-server) and [security guidance](https://developers.google.com/workspace/guides/configure-mcp-security) before enabling a runtime integration.

## Telegram webhook

Configure `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, and a comma-separated `TELEGRAM_ALLOWED_USER_IDS` allowlist. Configure `GOOGLE_CLOUD_PROJECT_ID`, `CLOUD_TASKS_LOCATION`, `CLOUD_TASKS_QUEUE`, and `CLOUD_TASKS_TARGET_URL` for the Cloud Tasks queue and its HTTP worker. `CLOUD_TASKS_TARGET_URL` must be the full worker URL, ending in `/tasks/process-message`, and `CLOUD_TASKS_SERVICE_ACCOUNT_EMAIL` must be the identity Cloud Tasks uses to create its OIDC token. The webhook is `POST /webhooks/telegram`; configure Telegram with the same secret token.

Webhook update IDs are claimed in Firestore before enqueueing and marked enqueued only after Cloud Tasks accepts the task. Task names are deterministic from update IDs, so Telegram retries and ambiguous enqueue responses do not create duplicate tasks. A transactional per-user fixed-window limit defaults to 10 requests per 60 seconds; over-limit webhook updates are acknowledged and dropped to prevent Telegram retries. A pending enqueue claim expires after five minutes so a crashed enqueue attempt can be retried.

The worker route verifies the Google-signed Cloud Tasks OIDC token, including its audience and `CLOUD_TASKS_SERVICE_ACCOUNT_EMAIL`. Grant that identity permission to invoke the Cloud Run service; the worker also performs its own token verification, so an obscure URL is not treated as authentication. Configure Firestore access for the runtime identity and set `ANTHROPIC_API_KEY` (plus `ANTHROPIC_MODEL` if you want a different model). `POST /tasks/process-message` loads a bounded conversation history, calls the orchestrator, saves the updated history and response before delivery, and reuses the saved response if Cloud Tasks retries after a send failure. History is keyed by channel, user, and conversation. The Telegram adapter currently sends text and attachment type notes; it does not fetch attachment contents.
