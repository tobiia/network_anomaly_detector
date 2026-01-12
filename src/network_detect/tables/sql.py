import sqlite3

def _init_database(self) -> None:
        """Initialize SQLite database with optimized schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main connections table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            uid TEXT PRIMARY KEY,
            ts REAL,
            ts_iso TEXT,
            duration REAL,
            proto TEXT,
            orig_h TEXT,
            resp_h TEXT,
            orig_p INTEGER,
            resp_p INTEGER,
            orig_pkts INTEGER,
            resp_pkts INTEGER,
            orig_bytes INTEGER,
            resp_bytes INTEGER,
            service TEXT,
            has_dns INTEGER,
            has_tls INTEGER,
            flow_bytes_per_sec REAL,
            pkts_per_sec REAL,
            pkt_ratio REAL,
            approx_fwd_pkt_len_mean REAL,
            approx_bwd_pkt_len_mean REAL,
            is_dns INTEGER DEFAULT 0,
            is_ssl INTEGER DEFAULT 0
        )
        ''')
        
        # DNS-specific table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_connections (
            uid TEXT PRIMARY KEY,
            query TEXT,
            qclass INTEGER,
            qtype INTEGER,
            rcode INTEGER,
            answers TEXT,  -- JSON array
            ttls TEXT,     -- JSON array
            rejected INTEGER,
            q_len INTEGER,
            q_entropy REAL,
            q_num_levels INTEGER,
            q_dig_ratio REAL,
            ans_len_mean REAL,
            ttl_mean REAL,
            FOREIGN KEY (uid) REFERENCES connections(uid)
        )
        ''')
        
        # SSL-specific table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssl_connections (
            uid TEXT PRIMARY KEY,
            version TEXT,
            cipher TEXT,
            server_name TEXT,
            resumed INTEGER,
            established INTEGER,
            ssl_history TEXT,
            ja4 TEXT,
            ja4s TEXT,
            cert_chain_fps TEXT,  -- JSON array
            client_ciphers TEXT,  -- JSON array
            ssl_client_exts TEXT, -- JSON array
            ssl_server_exts TEXT, -- JSON array
            num_cli_exts INTEGER,
            num_srv_exts INTEGER,
            num_certs INTEGER,
            weak_cipher INTEGER,
            FOREIGN KEY (uid) REFERENCES connections(uid)
        )
        ''')
        
        conn.commit()
        conn.close()

def _store_in_database(self) -> None:
        """Batch insert all connections into SQLite database"""
        if not self.connections:
            return
        
        conn = sqlite3.connect(self.db_path)
        
        # Prepare data for batch insertion
        conn_rows, dns_rows, ssl_rows = [], [], []
        
        for uid, connection in self.connections.items():
            # Base connection data
            conn_rows.append((
                connection.uid, connection.ts, connection.ts_iso,
                connection.duration, connection.proto, connection.orig_h,
                connection.resp_h, connection.orig_p, connection.resp_p,
                connection.orig_pkts, connection.resp_pkts,
                connection.orig_bytes, connection.resp_bytes,
                connection.service, connection.has_dns, connection.has_tls,
                connection.flow_bytes_per_sec, connection.pkts_per_sec,
                connection.pkt_ratio, connection.approx_fwd_pkt_len_mean,
                connection.approx_bwd_pkt_len_mean,
                isinstance(connection, DNSConnection),
                isinstance(connection, SSLConnection)
            ))
            
            # DNS-specific data
            if isinstance(connection, DNSConnection):
                dns_rows.append((
                    connection.uid, connection.query, connection.qclass,
                    connection.qtype, connection.rcode,
                    json.dumps(connection.answers),
                    json.dumps(connection.ttls),
                    connection.rejected, connection.q_len,
                    connection.q_entropy, connection.q_num_levels,
                    connection.q_dig_ratio, connection.ans_len_mean,
                    connection.ttl_mean
                ))
            
            # SSL-specific data
            if isinstance(connection, SSLConnection):
                ssl_rows.append((
                    connection.uid, connection.version, connection.cipher,
                    connection.server_name, connection.resumed,
                    connection.established, connection.ssl_history,
                    connection.ja4, connection.ja4s,
                    json.dumps(connection.cert_chain_fps),
                    json.dumps(connection.client_ciphers),
                    json.dumps(connection.ssl_client_exts),
                    json.dumps(connection.ssl_server_exts),
                    connection.num_cli_exts, connection.num_srv_exts,
                    connection.num_certs, connection.weak_cipher
                ))
        
        # Batch insert
        cursor = conn.cursor()
        
        # Insert base connections (replace if exists)
        cursor.executemany('''
            INSERT OR REPLACE INTO connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', conn_rows)
        
        # Insert DNS connections
        if dns_rows:
            cursor.executemany('''
                INSERT OR REPLACE INTO dns_connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', dns_rows)
        
        # Insert SSL connections
        if ssl_rows:
            cursor.executemany('''
                INSERT OR REPLACE INTO ssl_connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', ssl_rows)
        
        conn.commit()
        conn.close()

def load_from_database(self, limit: Optional[int] = None) -> None:
        """Load connections from database (for analysis or additional training)"""
        conn = sqlite3.connect(self.db_path)
        
        # Load base connections
        query = "SELECT * FROM connections"
        if limit:
            query += f" LIMIT {limit}"
        
        df_conn = pd.read_sql_query(query, conn)
        
        # Load DNS connections
        df_dns = pd.read_sql_query("SELECT * FROM dns_connections", conn)
        
        # Load SSL connections
        df_ssl = pd.read_sql_query("SELECT * FROM ssl_connections", conn)
        
        conn.close()
        
        # Reconstruct Connection objects (simplified - you'd add full reconstruction)
        for _, row in df_conn.iterrows():
            if row['uid'] in df_dns['uid'].values:
                # Reconstruct DNSConnection
                pass
            elif row['uid'] in df_ssl['uid'].values:
                # Reconstruct SSLConnection
                pass
            else:
                # Reconstruct base Connection
                pass