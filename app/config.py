from pydantic import AnyHttpUrl, TypeAdapter
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
	model_config = SettingsConfigDict(
		env_file=".env",
		env_file_encoding="utf-8",
		extra="ignore",
	)

	drive_mcp_enabled: bool = False
	drive_mcp_url: AnyHttpUrl = TypeAdapter(AnyHttpUrl).validate_python(
		"https://drivemcp.googleapis.com/mcp/v1"
	)
	telegram_bot_token: str = ""
	telegram_webhook_secret: str = ""
	telegram_allowed_user_ids: str = ""
	google_cloud_project_id: str = ""
	cloud_tasks_location: str = ""
	cloud_tasks_queue: str = ""
	cloud_tasks_target_url: str = ""
	cloud_tasks_service_account_email: str = ""
	telegram_idempotency_collection: str = "telegram_updates"
	telegram_rate_limit_collection: str = "telegram_rate_limits"
	telegram_rate_limit_requests: int = 10
	telegram_rate_limit_window_seconds: int = 60
	conversation_collection: str = "conversations"
	conversation_history_limit: int = 40
	anthropic_api_key: str = ""
	anthropic_model: str = "claude-sonnet-4-6"
	anthropic_max_tokens: int = 1024
	azure_tenant_id: str = ""
	azure_client_id: str = ""
	azure_client_secret: str = ""

	@property
	def active_drive_mcp_url(self) -> str | None:
		if not self.drive_mcp_enabled:
			return None
		return str(self.drive_mcp_url)

	@property
	def telegram_allowed_user_id_set(self) -> frozenset[str]:
		return frozenset(
			user_id.strip()
			for user_id in self.telegram_allowed_user_ids.split(",")
			if user_id.strip()
		)
