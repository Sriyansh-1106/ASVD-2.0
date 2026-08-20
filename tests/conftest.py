"""ASVD Demo — Shared Test Fixtures.

Provides common fixtures used across all test modules.
"""

import os
import pytest
import pandas as pd


# ── Paths ──────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")

DATASET_CSV = os.path.join(DATA_DIR, "synthetic_cyber_calls.csv")
DATASET_JSON = os.path.join(DATA_DIR, "synthetic_cyber_calls.json")

TRAIN_CSV = os.path.join(PROCESSED_DIR, "train.csv")
VAL_CSV = os.path.join(PROCESSED_DIR, "val.csv")
TEST_CSV = os.path.join(PROCESSED_DIR, "test.csv")


# ── Required Schema ───────────────────────────────────────────────────

REQUIRED_COLUMNS = [
    "conversation_id",
    "conversation_text",
    "label",
    "scam_category",
    "threat_level",
    "urgency",
    "authority_impersonation",
    "financial_request",
    "otp_request",
    "credential_request",
    "threat_detected",
    "emotional_manipulation",
    "secrecy_request",
    "detected_indicators",
    "recommended_action",
]

SCAM_CATEGORIES = [
    "Family Impersonation",
    "Friend Impersonation",
    "Police Impersonation",
    "Government Impersonation",
    "Bank Fraud",
    "OTP Scam",
    "PIN/Credential Scam",
    "Investment Scam",
    "Job Scam",
    "Loan Scam",
    "Extortion",
    "Blackmail",
    "Emergency Money Scam",
    "Fake Parcel/Customs Scam",
    "Financial Manipulation",
]

VALID_LABELS = {"SCAM", "SAFE"}
VALID_THREAT_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
BINARY_COLUMNS = [
    "urgency",
    "authority_impersonation",
    "financial_request",
    "otp_request",
    "credential_request",
    "threat_detected",
    "emotional_manipulation",
    "secrecy_request",
]


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def dataset_path():
    """Return path to the main dataset CSV."""
    return DATASET_CSV


@pytest.fixture(scope="session")
def dataset(dataset_path):
    """Load the dataset CSV into a DataFrame.

    Skips all tests if the file doesn't exist yet (TDD Red phase).
    """
    if not os.path.exists(dataset_path):
        pytest.skip(f"Dataset not generated yet: {dataset_path}")
    return pd.read_csv(dataset_path, encoding="utf-8-sig")


@pytest.fixture(scope="session")
def train_df():
    """Load the training split."""
    if not os.path.exists(TRAIN_CSV):
        pytest.skip(f"Train split not generated yet: {TRAIN_CSV}")
    return pd.read_csv(TRAIN_CSV, encoding="utf-8-sig")


@pytest.fixture(scope="session")
def val_df():
    """Load the validation split."""
    if not os.path.exists(VAL_CSV):
        pytest.skip(f"Validation split not generated yet: {VAL_CSV}")
    return pd.read_csv(VAL_CSV, encoding="utf-8-sig")


@pytest.fixture(scope="session")
def test_df():
    """Load the test split."""
    if not os.path.exists(TEST_CSV):
        pytest.skip(f"Test split not generated yet: {TEST_CSV}")
    return pd.read_csv(TEST_CSV, encoding="utf-8-sig")
