import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import msal
import requests

from app.config import Settings


GRAPH_SIGN_INS_URL = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
REQUEST_TIMEOUT_SECONDS = (10, 60)
SIGN_IN_LOOKBACK_DAYS = 7
SIGN_IN_FIELDS = (
	"createdDateTime,userDisplayName,userPrincipalName,appDisplayName,"
	"ipAddress,status,location,deviceDetail,conditionalAccessStatus"
)


def get_access_token(settings: Settings) -> str:
	if not all(
		(settings.azure_tenant_id, settings.azure_client_id, settings.azure_client_secret)
	):
		raise RuntimeError("Azure Entra ID credentials are not fully configured")

	application = msal.ConfidentialClientApplication(
		settings.azure_client_id,
		authority=f"https://login.microsoftonline.com/{settings.azure_tenant_id}",
		client_credential=settings.azure_client_secret,
	)
	result = application.acquire_token_for_client(scopes=[GRAPH_SCOPE])
	access_token = result.get("access_token")
	if not access_token:
		raise RuntimeError(
			result.get("error_description", "Could not get Microsoft Graph access token")
		)
	return access_token


def normalize_sign_in_event(event: dict[str, Any]) -> dict[str, Any]:
	location = event.get("location") or {}
	device = event.get("deviceDetail") or {}
	status = event.get("status") or {}
	error_code = status.get("errorCode")
	if error_code is None:
		result = "unknown"
	else:
		result = "success" if error_code == 0 else "failure"

	return {
		"user": event.get("userPrincipalName") or event.get("userDisplayName"),
		"timestamp": event.get("createdDateTime"),
		"ip": event.get("ipAddress"),
		"country": location.get("countryOrRegion"),
		"city": location.get("city"),
		"app": event.get("appDisplayName"),
		"result": result,
		"browser": device.get("browser"),
		"os": device.get("operatingSystem"),
		"device_managed": device.get("isManaged"),
		"device_compliant": device.get("isCompliant"),
		"authentication_requirement": None,
		"conditional_access_status": event.get("conditionalAccessStatus"),
	}


def get_recent_sign_ins(settings: Settings, limit: int = 10) -> list[dict[str, Any]]:
	access_token = get_access_token(settings)
	since = (datetime.now(timezone.utc) - timedelta(days=SIGN_IN_LOOKBACK_DAYS))
	since = since.isoformat(timespec="seconds").replace("+00:00", "Z")
	response = requests.get(
		GRAPH_SIGN_INS_URL,
		headers={"Authorization": f"Bearer {access_token}"},
		params={
			"$top": limit,
			"$filter": f"createdDateTime ge {since}",
			"$orderby": "createdDateTime desc",
			"$select": SIGN_IN_FIELDS,
		},
		timeout=REQUEST_TIMEOUT_SECONDS,
	)
	if response.status_code != 200:
		response.raise_for_status()
		raise requests.HTTPError(
			f"Microsoft Graph returned HTTP {response.status_code}", response=response
		)

	logging.info("Microsoft Graph sign-in request returned HTTP 200")
	events = response.json().get("value")
	if not isinstance(events, list):
		raise RuntimeError("Microsoft Graph returned an invalid sign-in response")
	return [normalize_sign_in_event(event) for event in events]


if __name__ == "__main__":
	events = get_recent_sign_ins(Settings())
	print(f"Microsoft Graph returned HTTP 200; retrieved {len(events)} sign-in events.")