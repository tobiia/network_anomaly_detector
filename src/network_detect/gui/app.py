from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple, Optional

import numpy as np
import pandas as pd
import tempfile
from pandas import DataFrame
import streamlit as st

from setup.zeek import process_file
from parse.parse_log import ParseLogs
from config import Config
from main import load_model_package, ensure_features  # keep your helpers


# STATE FUNCTIONS

def init_state() -> None:
    # saving parsed dfs (pcaps) + the current pcap active/the user is looking at
    # session_state["pcaps"][pcap_name] = {"dns": df, "tls": df}
    if "pcaps" not in st.session_state:
        st.session_state["pcaps"] = {}
    if "active_pcap" not in st.session_state:
        st.session_state["active_pcap"] = None


def store_parsed_dfs(pcap_name: str, dns_df: DataFrame, tls_df: DataFrame) -> None:
    st.session_state["pcaps"][pcap_name] = {
        "dns": {"df": dns_df, "threshold": None},
        "tls": {"df": tls_df, "threshold": None},
    }
    st.session_state["active_pcap"] = pcap_name


def get_active_record() -> Dict:
    name = st.session_state.get("active_pcap")
    return st.session_state["pcaps"].get(name)


# ML FUNCTIONS

def predict_with_threshold(
    df: DataFrame,
    package: Dict,
) -> DataFrame:
    
    model = package["model"]
    expected_features = package["features"]
    threshold = package["threshold"]

    df_feat = ensure_features(df, expected_features)[expected_features]

    if hasattr(model, "predict_proba"):
        score = model.predict_proba(df_feat)[:, 1]
    else:
        score = model.predict(df_feat).astype(float)

    pred = (score >= threshold).astype(int)

    df["score"] = score
    df["pred"] = pred
    df["pred_label"] = np.where(pred == 1, "malicious", "benign")
    return df


def basic_metrics(df: DataFrame) -> Tuple[int, float, int]:
    if df.empty or "pred" not in df.columns:
        return 0, 0.0, len(df)

    threats = df[df["pred"] == 1]
    threat_count = int(len(threats))
    avg_conf = float(threats["score"].mean()) if threat_count else 0.0
    benign_count = int((df["pred"] == 0).sum())
    return threat_count, avg_conf, benign_count


def df_to_download(df: DataFrame):
    return df.to_csv(index=False).encode("utf-8")


# PCAP FUNCTIONS

@st.cache_resource
def get_parser() -> ParseLogs:
    return ParseLogs()

# main()
def pcap_to_df(pcap_path: Path) -> Tuple[DataFrame, DataFrame]:
    parser = get_parser()
    with process_file(pcap_path) as log_dir:
        dns_conns, tls_conns = parser.parse_logs(log_dir)

    dns_df = parser.to_dataframe(dns_conns)
    tls_df = parser.to_dataframe(tls_conns)

    return dns_df, tls_df


# UI

def get_model_path(flow_type: str) -> Path:
    if flow_type == "dns":
        return Path(Config.MODEL_DIR) / "dns_model_package.pkl"
    return Path(Config.MODEL_DIR) / "tls_model_package.pkl"


def preferred_columns(df: DataFrame) -> list[str]:
    preferred = [
        "ts", "id.orig_h", "id.resp_h", "id.resp_p",
        "server_name", "query",
        "score", "pred_label"
    ]
    cols = [c for c in preferred if c in df.columns]
    return cols if cols else df.columns.tolist()

# APPLICATION

def main():
    st.set_page_config(page_title="Infer-IDS", layout="wide")
    st.title("Infer-IDS")

    init_state()

    with st.sidebar:
        st.header("Settings")
        flow_choice = st.selectbox("View", ["dns", "tls"])
        st.divider()

    # uploader
    st.subheader("Upload PCAP File")
    pcap = st.file_uploader("Upload pcap file to analyze", "pcap")

    if pcap is not None:
        with st.spinner(f"Parsing {pcap.name} with Zeek..."):
            try:
                # FIXME -- can't get pcap path using file_uploader
                dns_df, tls_df = pcap_to_df(pcap_path)
            except Exception as e:
                st.error(f"Failed parsing {pcap.name}: {e}")
                return

        store_parsed_dfs(pcap.name, dns_df, tls_df)
        st.success(f"Loaded: {pcap.name}")
    else:
        st.warning("Something went wrong while parsing pcap file")
        return

    # retrieve dfs for this pcap
    record = get_active_record() # dict of the 2 dfs
    if record is None:
        st.info("Upload a PCAP file to begin.")
        return

    # display df user has chosen (flow_choice = button, dns or tls)
    df_current = record[flow_choice]

    st.divider()
    st.subheader(f"{flow_choice.upper()} View")

    pkg_path = get_model_path(flow_choice)

    left, right = st.columns([1, 2])

    with left:
        run_predict = st.button("Run / Update Predictions")

    already_pred = bool(df_current["pred"])

    # update df with classification scores
    if run_predict:
        try:
            package = load_model_package(pkg_path)
            df_pred = predict_with_threshold(df_current, package)
        except Exception as e:
            st.error(f"Prediction failed: {e}")
            return
        
        # save mutated df in session state
        record[flow_choice] = df_pred


if __name__ == "__main__":
    main()