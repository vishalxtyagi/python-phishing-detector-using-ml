"""
Train an XGBoost phishing detection model using the ARFF training dataset.

Usage:
    python train.py                        # uses default dataset path
    python train.py --dataset path/to.arff
    python train.py --output my_model.pkl

The trained model is saved to ml/model.pkl by default and is automatically
loaded by the API on startup.
"""
import argparse
import logging
import os
import pickle
import sys

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATASET = os.path.join(REPO_ROOT, "Training Dataset.arff")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "model.pkl")

# ---------------------------------------------------------------------------
# Feature names used during training (must match the ARFF attribute order
# minus the class label)
# ---------------------------------------------------------------------------
ARFF_FEATURES = [
    "having_IP_Address", "URL_Length", "Shortining_Service",
    "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
    "having_Sub_Domain", "Domain_registeration_length", "Favicon", "port",
    "HTTPS_token", "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH",
    "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover",
    "RightClick", "popUpWidnow", "Iframe", "age_of_domain", "DNSRecord",
    "web_traffic",
]


def load_arff(path: str):
    """Parse an ARFF file and return (X, y) numpy arrays."""
    try:
        from scipy.io import arff as scipy_arff
        import pandas as pd
        data, meta = scipy_arff.loadarff(path)
        df = pd.DataFrame(data)
        # The last column is the class label
        label_col = df.columns[-1]
        y = df[label_col].astype(int).values
        X = df.drop(columns=[label_col]).astype(float).values
        return X, y
    except Exception as exc:
        logger.error("Failed to load ARFF file: %s", exc)
        sys.exit(1)


def train(dataset_path: str, output_path: str, test_size: float = 0.2):
    """Train an XGBoost classifier and save it to disk."""
    logger.info("Loading dataset from %s", dataset_path)
    X, y = load_arff(dataset_path)
    logger.info("Dataset shape: %s  |  label distribution: %s", X.shape,
                dict(zip(*np.unique(y, return_counts=True))))

    # Map labels: ARFF uses -1/0/1; convert to binary 0/1 (1 = phishing)
    y_binary = np.where(y == 1, 1, 0)

    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report, accuracy_score
    import xgboost as xgb

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary, test_size=test_size, random_state=42, stratify=y_binary
    )

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    logger.info("Training XGBoost model …")
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    logger.info("Test accuracy: %.4f", acc)
    logger.info("\n%s", classification_report(y_test, y_pred,
                target_names=["legitimate", "phishing"]))

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(model, f)
    logger.info("Model saved to %s", output_path)


def main():
    parser = argparse.ArgumentParser(description="Train phishing detection model")
    parser.add_argument("--dataset", default=DEFAULT_DATASET,
                        help="Path to Training Dataset.arff")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="Output path for model.pkl")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Fraction of data used for testing (default 0.2)")
    args = parser.parse_args()

    if not os.path.exists(args.dataset):
        logger.error("Dataset not found: %s", args.dataset)
        sys.exit(1)

    train(args.dataset, args.output, args.test_size)


if __name__ == "__main__":
    main()
