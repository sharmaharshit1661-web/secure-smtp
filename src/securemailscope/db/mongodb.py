"""
MongoDB connection and collection management for Secure SMTP.

Provides connection pooling, collection accessors, sequence generators for integer IDs,
indexing, and document serialization helpers.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.database import Database

logger = logging.getLogger(__name__)

# Configurable MongoDB URI and Database Name
MONGO_URI = os.environ.get("SECURE_SMTP_MONGO_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.environ.get("SECURE_SMTP_MONGO_DB", "secure_smtp")

_client: MongoClient | None = None


def get_mongo_client(uri: str | None = None) -> MongoClient:
    """Get or initialize singleton PyMongo MongoClient."""
    global _client
    if _client is None or uri is not None:
        target_uri = uri or MONGO_URI
        _client = MongoClient(
            target_uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            tz_aware=True,
        )
    return _client


def get_database(db_name: str | None = None) -> Database:
    """Get the active MongoDB database instance."""
    client = get_mongo_client()
    return client[db_name or DATABASE_NAME]


# ── Collection Accessors ──


def get_hosts_col():
    """Access the `hosts` collection."""
    return get_database()["hosts"]


def get_sessions_col():
    """Access the `sessions` collection."""
    return get_database()["sessions"]


def get_jobs_col():
    """Access the `analysis_jobs` collection."""
    return get_database()["analysis_jobs"]


def get_counters_col():
    """Access the `counters` collection for integer ID generation."""
    return get_database()["counters"]


# ── Sequence Helper for Integer IDs ──


def get_next_sequence(name: str) -> int:
    """
    Generate an atomic auto-incrementing integer ID for entities (host_id, session_id).
    Ensures seamless compatibility with numerical IDs used in APIs and dashboards.
    """
    col = get_counters_col()
    result = col.find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return result["seq"]


# ── Database Lifecycle Helpers ──


def init_db_indexes() -> None:
    """Initialize performance and uniqueness indexes on collections."""
    try:
        hosts = get_hosts_col()
        hosts.create_index([("ip_or_hostname", ASCENDING)], unique=True)
        hosts.create_index([("id", ASCENDING)], unique=True)
        hosts.create_index([("aggregate_risk_score", DESCENDING)])

        sessions = get_sessions_col()
        sessions.create_index([("id", ASCENDING)], unique=True)
        sessions.create_index([("host_id", ASCENDING)])
        sessions.create_index([("pcap_source", ASCENDING)])

        jobs = get_jobs_col()
        jobs.create_index([("job_id", ASCENDING)], unique=True)
        logger.info("MongoDB indexes successfully created on database: %s", DATABASE_NAME)
    except Exception as e:
        logger.warning("Failed to initialize MongoDB indexes: %s", e)


def drop_database() -> None:
    """Drop the database — use for testing / clean wipe."""
    client = get_mongo_client()
    client.drop_database(DATABASE_NAME)
    logger.info("MongoDB database '%s' dropped.", DATABASE_NAME)


def serialize_doc(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    """
    Recursively serialize MongoDB document for JSON / API responses.
    Converts ObjectId to string, ISO-formats datetimes, and ensures clean dict keys.
    """
    if doc is None:
        return None
    res = {}
    for k, v in doc.items():
        if k == "_id":
            res["mongo_id"] = str(v)
        elif isinstance(v, datetime):
            res[k] = v.isoformat()
        elif isinstance(v, dict):
            res[k] = serialize_doc(v)
        elif isinstance(v, list):
            res[k] = [serialize_doc(item) if isinstance(item, dict) else item for item in v]
        else:
            res[k] = v
    return res
