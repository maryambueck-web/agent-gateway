from functools import lru_cache

from google.cloud import firestore

from app.config import Settings


@lru_cache(maxsize=1)
def get_firestore_client() -> firestore.Client:
	project_id = Settings().google_cloud_project_id
	return firestore.Client(project=project_id or None)