"""ASVD Demo — Dataset Validation Tests.

TDD Red Phase: These tests are written BEFORE the dataset generator.
They define what a valid synthetic cyber-scam dataset must look like.

Run:
    python -m pytest tests/test_dataset.py -v
"""

import os
import re
from tests.conftest import (
    REQUIRED_COLUMNS,
    SCAM_CATEGORIES,
    VALID_LABELS,
    VALID_THREAT_LEVELS,
    BINARY_COLUMNS,
)



# ══════════════════════════════════════════════════════════════════════
# 1. FILE EXISTENCE
# ══════════════════════════════════════════════════════════════════════

class TestDatasetFileExists:
    """The dataset CSV must exist on disk after generation."""

    def test_dataset_file_exists(self, dataset_path):
        assert os.path.exists(dataset_path), (
            f"Dataset file not found: {dataset_path}\n"
            f"Run: python data/generate_dataset.py"
        )


# ══════════════════════════════════════════════════════════════════════
# 2. SCHEMA & SIZE
# ══════════════════════════════════════════════════════════════════════

class TestDatasetSchema:
    """The dataset must have the correct structure."""

    def test_dataset_not_empty(self, dataset):
        """Dataset should have at least 2000 rows."""
        assert len(dataset) >= 2000, (
            f"Expected >= 2000 rows, got {len(dataset)}"
        )

    def test_dataset_columns(self, dataset):
        """All 15 required columns must be present."""
        missing = set(REQUIRED_COLUMNS) - set(dataset.columns)
        assert not missing, (
            f"Missing columns: {missing}"
        )

    def test_no_extra_unnamed_columns(self, dataset):
        """No stray 'Unnamed:' columns from pandas artefacts."""
        unnamed = [c for c in dataset.columns if c.startswith("Unnamed")]
        assert not unnamed, f"Unexpected columns: {unnamed}"


# ══════════════════════════════════════════════════════════════════════
# 3. LABEL VALIDATION
# ══════════════════════════════════════════════════════════════════════

class TestLabels:
    """Labels must be well-formed."""

    def test_valid_labels(self, dataset):
        """Every label must be SCAM or SAFE."""
        invalid = set(dataset["label"].unique()) - VALID_LABELS
        assert not invalid, f"Invalid labels found: {invalid}"

    def test_label_balance(self, dataset):
        """Neither class should be less than 30% of the dataset."""
        counts = dataset["label"].value_counts(normalize=True)
        for label in VALID_LABELS:
            assert label in counts.index, f"Missing label: {label}"
            assert counts[label] >= 0.30, (
                f"Label '{label}' is only {counts[label]:.1%} — "
                f"expected >= 30%"
            )

    def test_safe_conversations_present(self, dataset):
        """There should be a meaningful number of safe conversations."""
        safe_count = (dataset["label"] == "SAFE").sum()
        assert safe_count >= 500, (
            f"Only {safe_count} SAFE conversations — need at least 500"
        )


# ══════════════════════════════════════════════════════════════════════
# 4. SCAM CATEGORIES
# ══════════════════════════════════════════════════════════════════════

class TestScamCategories:
    """All 15 scam categories must appear in the dataset."""

    def test_scam_categories_present(self, dataset):
        scam_df = dataset[dataset["label"] == "SCAM"]
        present = set(scam_df["scam_category"].unique())
        missing = set(SCAM_CATEGORIES) - present
        assert not missing, (
            f"Missing scam categories: {missing}"
        )

    def test_each_category_has_samples(self, dataset):
        """Each scam category should have at least 50 samples."""
        scam_df = dataset[dataset["label"] == "SCAM"]
        for cat in SCAM_CATEGORIES:
            count = (scam_df["scam_category"] == cat).sum()
            assert count >= 50, (
                f"Category '{cat}' has only {count} samples — need >= 50"
            )


# ══════════════════════════════════════════════════════════════════════
# 5. CONVERSATION TEXT QUALITY
# ══════════════════════════════════════════════════════════════════════

class TestConversationText:
    """Conversation text must be non-empty and unique."""

    def test_no_empty_conversations(self, dataset):
        """No blank conversation_text values."""
        empty = dataset["conversation_text"].isna() | (
            dataset["conversation_text"].str.strip() == ""
        )
        assert not empty.any(), (
            f"Found {empty.sum()} empty conversation texts"
        )

    def test_no_duplicate_conversations(self, dataset):
        """No identical conversation texts."""
        dupes = dataset["conversation_text"].duplicated().sum()
        assert dupes == 0, (
            f"Found {dupes} duplicate conversation texts"
        )

    def test_conversation_min_length(self, dataset):
        """Each conversation should be at least 20 characters."""
        short = dataset["conversation_text"].str.len() < 20
        assert not short.any(), (
            f"Found {short.sum()} conversations shorter than 20 chars"
        )


# ══════════════════════════════════════════════════════════════════════
# 6. CONVERSATION ID FORMAT
# ══════════════════════════════════════════════════════════════════════

class TestConversationId:
    """Conversation IDs must follow the ASVD_XXXXXX pattern."""

    def test_conversation_id_format(self, dataset):
        """IDs must match ASVD_XXXXXX (6 digits)."""
        pattern = re.compile(r"^ASVD_\d{6}$")
        invalid = dataset["conversation_id"].apply(
            lambda x: not bool(pattern.match(str(x)))
        )
        assert not invalid.any(), (
            f"Found {invalid.sum()} IDs not matching ASVD_XXXXXX format. "
            f"Examples: {dataset.loc[invalid, 'conversation_id'].head().tolist()}"
        )

    def test_conversation_id_unique(self, dataset):
        """No duplicate conversation IDs."""
        dupes = dataset["conversation_id"].duplicated().sum()
        assert dupes == 0, (
            f"Found {dupes} duplicate conversation IDs"
        )


# ══════════════════════════════════════════════════════════════════════
# 7. THREAT LEVEL & BINARY FIELDS
# ══════════════════════════════════════════════════════════════════════

class TestFieldValues:
    """Threat levels and binary indicator fields must be valid."""

    def test_threat_level_values(self, dataset):
        """Threat levels must be LOW, MEDIUM, HIGH, or CRITICAL."""
        invalid = set(dataset["threat_level"].unique()) - VALID_THREAT_LEVELS
        assert not invalid, f"Invalid threat levels: {invalid}"

    def test_binary_fields(self, dataset):
        """Binary indicator columns must only contain 0 or 1."""
        for col in BINARY_COLUMNS:
            invalid = set(dataset[col].unique()) - {0, 1}
            assert not invalid, (
                f"Column '{col}' has non-binary values: {invalid}"
            )


# ══════════════════════════════════════════════════════════════════════
# 8. DETECTED INDICATORS & ACTIONS
# ══════════════════════════════════════════════════════════════════════

class TestIndicatorsAndActions:
    """Indicator strings and recommended actions must be well-formed."""

    def test_detected_indicators_format(self, dataset):
        """detected_indicators should be pipe-delimited or 'none'."""
        pattern = re.compile(r"^(none|[a-z_]+(\|[a-z_]+)*)$")
        invalid = dataset["detected_indicators"].apply(
            lambda x: not bool(pattern.match(str(x).strip()))
        )
        assert not invalid.any(), (
            f"Found {invalid.sum()} rows with bad indicator format. "
            f"Examples: {dataset.loc[invalid, 'detected_indicators'].head().tolist()}"
        )

    def test_recommended_action_not_empty(self, dataset):
        """Every row must have a recommended action."""
        empty = dataset["recommended_action"].isna() | (
            dataset["recommended_action"].str.strip() == ""
        )
        assert not empty.any(), (
            f"Found {empty.sum()} rows with no recommended action"
        )

    def test_safe_conversations_have_no_threat_indicators(self, dataset):
        """SAFE conversations should mostly have 'none' for indicators."""
        safe = dataset[dataset["label"] == "SAFE"]
        with_indicators = safe[safe["detected_indicators"] != "none"]
        # Allow some safe conversations to have mild indicators (realistic)
        ratio = len(with_indicators) / len(safe) if len(safe) > 0 else 0
        assert ratio <= 0.15, (
            f"{ratio:.1%} of SAFE conversations have indicators — "
            f"expected <= 15%"
        )
