import json
from pathlib import Path
from typing import Dict, Iterator
import pandas as pd
import numpy as np

from config import Config
from connection import Connection
from dns_connection import DNSConnection
from ssl_connection import SSLConnection

class ParseLogs:
    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        self.dns_connections: Dict[str, Connection] = {}
        self.ssl_connections: Dict[str, Connection] = {}
    
    def iter_json(self, path: Path) -> Iterator[dict]:
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    yield json.loads(line)
        except FileNotFoundError:
            return
    
    def parse_logs(self, run_id: str) -> Dict[str, Connection]:

        run_path = Path(Config.RUNS_DIR) / run_id
        
        self.connections.clear()
        
        conn_path = run_path / "conn.log"
        self._parse_conn_log(conn_path)
        
        # append DNS info
        dns_path = run_path / "dns.log"
        if dns_path.exists():
            self._add_dns_info(dns_path)
        
        # append SSL info
        ssl_path = run_path / "ssl.log"
        if ssl_path.exists():
            self._add_ssl_info(ssl_path)
        
        # Store in database
        #self._store_in_database() TODO
        
        return self.connections
    
    def _parse_conn_log(self, conn_path: Path) -> None:
        for record in self.iter_json(conn_path):
            conn = Connection.parse_conn_record(record)
            if conn:
                self.connections[conn.uid] = conn
    
    def _add_dns_info(self, dns_path: Path) -> None:
        for record in self.iter_json(dns_path):
            uid = record.get("uid", "")
            if uid and uid in self.connections.keys():
                conn = self.connections[uid]
                dns_conn = DNSConnection.parse_dns_record(record, conn)
                if dns_conn:
                    self.dns_connections[uid] = dns_conn
    
    def _add_ssl_info(self, ssl_path: Path) -> None:
        for record in self.iter_json(ssl_path):
            uid = record.get("uid", "")
            if uid and uid in self.connections.keys():
                conn = self.connections[uid]
                ssl_conn = SSLConnection.parse_ssl_record(record, conn)
                if ssl_conn:
                    self.ssl_connections[uid] = ssl_conn
    
    def to_dataframe(self, include_features: bool = True) -> pd.DataFrame:
        rows = []
        
        for connection in self.connections.values():
            row = {
                "uid": connection.uid,
                "ts": connection.ts,
                "ts_iso": connection.ts_iso,
                "duration": connection.duration,
                "proto": connection.proto,
                "orig_bytes": connection.orig_bytes,
                "resp_bytes": connection.resp_bytes,
                "orig_pkts": connection.orig_pkts,
                "resp_pkts": connection.resp_pkts,
                "flow_bytes_per_sec": connection.flow_bytes_per_sec,
                "pkts_per_sec": connection.pkts_per_sec,
                "pkt_ratio": connection.pkt_ratio,
                "approx_fwd_pkt_len_mean": connection.approx_fwd_pkt_len_mean,
                "approx_bwd_pkt_len_mean": connection.approx_bwd_pkt_len_mean,
                "has_dns": connection.has_dns,
                "has_tls": connection.has_tls,
            }
            
            # add dns features if avail
            if isinstance(connection, DNSConnection) and include_features:
                row.update({
                    "dns_query_len": connection.q_len,
                    "dns_entropy": connection.q_entropy,
                    "dns_num_levels": connection.q_num_levels,
                    "dns_dig_ratio": connection.q_dig_ratio,
                    "dns_rcode": connection.rcode,
                    "dns_rejected": connection.rejected,
                })
            
            # ssl
            if isinstance(connection, SSLConnection) and include_features:
                row.update({
                    "ssl_version": connection.version,
                    "ssl_cipher": connection.cipher,
                    "ssl_weak_cipher": connection.weak_cipher,
                    "ssl_num_certs": connection.num_certs,
                    "ssl_num_cli_exts": connection.num_cli_exts,
                    "ssl_num_srv_exts": connection.num_srv_exts,
                })
            
            rows.append(row)
        
        return pd.DataFrame(rows)
    
    # TODO
    def get_ml_ready_features(self):
        """Extract features ready for ML algorithms"""
        df = self.to_dataframe(include_features=True)
        
        # Select feature columns (exclude metadata)
        feature_columns = [
            "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
            "flow_bytes_per_sec", "pkts_per_sec", "pkt_ratio",
            "approx_fwd_pkt_len_mean", "approx_bwd_pkt_len_mean",
            "has_dns", "has_tls", "dns_query_len", "dns_entropy",
            "dns_num_levels", "dns_dig_ratio", "dns_rcode", "dns_rejected",
            "ssl_weak_cipher", "ssl_num_certs", "ssl_num_cli_exts", "ssl_num_srv_exts"
        ]
        
        # Filter to available columns
        available_features = [col for col in feature_columns if col in df.columns]
        
        # Convert to numpy arrays
        X = df[available_features].fillna(0).values.astype(np.float32)
        
        # Create simple labels based on anomalies (for example, high DNS entropy or weak SSL)
        # You'll replace this with your actual labeling logic
        y = np.zeros(len(df))
        if "dns_entropy" in df.columns:
            y[df["dns_entropy"] > 3.0] = 1  # High entropy DNS
        if "ssl_weak_cipher" in df.columns:
            y[df["ssl_weak_cipher"] == 1] = 1  # Weak cipher
        
        return X, y, available_features