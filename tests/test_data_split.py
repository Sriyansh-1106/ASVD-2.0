"""ASVD Demo — Train/Validation/Test Split Tests.

TDD Red Phase: Validates the 70/15/15 stratified split.

Run:
    python -m pytest tests/test_data_split.py -v
"""

import os
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
TRAIN_CSV = os.path.join(PROCESSED_DIR, "train.csv")
VAL_CSV = os.path.join(PROCESSED_DIR, "val.csv")
TEST_CSV = os.path.join(PROCESSED_DIR, "test.csv")


# ══════════════════════════════════════════════════════════════════════
# 1. SPLIT FILES EXIST
# ══════════════════════════════════════════════════════════════════════

class TestSplitFilesExist:
    """Train, validation, and test CSVs must be generated."""

    def test_train_file_exists(self):
        assert os.path.exists(TRAIN_CSV), (
            f"Train split not found: {TRAIN_CSV}"
        )

    def test_val_file_exists(self):
        assert os.path.exists(VAL_CSV), (
            f"Validation split not found: {VAL_CSV}"
        )

    def test_test_file_exists(self):
        assert os.path.exists(TEST_CSV), (
            f"Test split not found: {TEST_CSV}"
        )


# ══════════════════════════════════════════════════════════════════════
# 2. SPLIT RATIOS
# ══════════════════════════════════════════════════════════════════════

class TestSplitRatios:
    """The split must follow 70/15/15 within ±2% tolerance."""

    def test_split_ratios(self, train_df, val_df, test_df):
        total = len(train_df) + len(val_df) + len(test_df)
        assert total > 0, "Total samples across splits is 0"

        train_ratio = len(train_df) / total
        val_ratio = len(val_df) / total
        test_ratio = len(test_df) / total

        assert abs(train_ratio - 0.70) <= 0.02, (
            f"Train ratio {train_ratio:.3f} not within 70% ± 2%"
        )
        assert abs(val_ratio - 0.15) <= 0.02, (
            f"Val ratio {val_ratio:.3f} not within 15% ± 2%"
        )
        assert abs(test_ratio - 0.15) <= 0.02, (
            f"Test ratio {test_ratio:.3f} not within 15% ± 2%"
        )


# ══════════════════════════════════════════════════════════════════════
# 3. NO DATA LEAKAGE
# ══════════════════════════════════════════════════════════════════════

class TestNoDataLeakage:
    """No conversation_id should appear in more than one split."""

    def test_no_leakage_train_val(self, train_df, val_df):
        overlap = set(train_df["conversation_id"]) & set(val_df["conversation_id"])
        assert not overlap, (
            f"Data leakage: {len(overlap)} IDs in both train and val"
        )

    def test_no_leakage_train_test(self, train_df, test_df):
        overlap = set(train_df["conversation_id"]) & set(test_df["conversation_id"])
        assert not overlap, (
            f"Data leakage: {len(overlap)} IDs in both train and test"
        )

    def test_no_leakage_val_test(self, val_df, test_df):
        overlap = set(val_df["conversation_id"]) & set(test_df["conversation_id"])
        assert not overlap, (
            f"Data leakage: {len(overlap)} IDs in both val and test"
        )


# ══════════════════════════════════════════════════════════════════════
# 4. STRATIFICATION
# ══════════════════════════════════════════════════════════════════════

class TestStratification:
    """Label distribution should be preserved across splits."""

    def test_label_distribution_preserved(self, train_df, val_df, test_df):
        """Each split should have roughly the same SCAM/SAFE ratio."""
        for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
            if len(df) == 0:
                pytest.fail(f"{name} split is empty")
            ratio = (df["label"] == "SCAM").mean()
            # The overall ratio is ~62.5%, allow ±5%
            assert 0.55 <= ratio <= 0.70, (
                f"{name} split SCAM ratio is {ratio:.3f} — "
                f"expected between 0.55 and 0.70"
            )
