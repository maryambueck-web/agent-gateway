from anthropic import Anthropic

from app.config import Settings


def respond(history: list[dict[str, str]], settings: Settings) -> str:
	if not settings.anthropic_api_key:
		raise RuntimeError("ANTHROPIC_API_KEY is not configured")

	client = Anthropic(api_key=settings.anthropic_api_key)
	result = client.messages.create(
		model=settings.anthropic_model,
		max_tokens=settings.anthropic_max_tokens,
		messages=history,
	)
	response = "\n".join(
		block.text for block in result.content if getattr(block, "type", None) == "text"
	)
	if not response:
		raise RuntimeError("The agent returned no text response")
	return response
