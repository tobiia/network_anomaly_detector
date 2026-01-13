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
    # state["pcaps"][pcap_name] = {"dns": df, "tls": df}
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


def get_active_record() -> Optional[Dict]:
    name = st.session_state.get("active_pcap")
    if not name:
        return None
    return st.session_state["pcaps"].get(name)


# ML FUNCTIONS

def predict_with_threshold(
    df: DataFrame,
    package: Dict,
    threshold: float,
) -> DataFrame:
    model = package["model"]
    expected_features = package["features"]

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
def parse_pcap_bytes_to_dfs(filename: str, raw_bytes: bytes) -> Tuple[DataFrame, DataFrame]:
    # REVIEW --> i think the main zeek processor should also use a temp file instead
    import tempfile

    parser = get_parser()

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        pcap_path = td_path / filename
        pcap_path.write_bytes(raw_bytes)

        # Create Zeek logs directory from PCAP
        log_dir = process_file(pcap_path)  # should return path to logs directory

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