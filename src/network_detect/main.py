from setup.zeek import process_file
from parse.parse_log import ParseLogs
from pathlib import Path
from config import Config
from pprint import pprint

class Main:
    
    def __init__(self):
        self.parser = ParseLogs()


    def main(self):
        # file dialog to get pcap
        #file_path = Config.PCAP_PATH
        #log_direct = process_file(file_path)
        log_direct = Config.LOG_PATH
        dns_connections, ssl_connections = self.parser.parse_logs(log_direct)
        dns_rows = self.parser.to_dataframe(dns_connections)
        ssl_rows = self.parser.to_dataframe(ssl_connections)
        pprint("------------------------------ FLOWS -----------------------------")
        pprint(dns_rows.head(1))
        pprint(ssl_rows.head(1))



        pprint("------------------------------ EVENTS -----------------------------")
        #pprint(dns_events_by_host["10.0.0.182"])
        pprint("------------------------------ WINDOWS -----------------------------")
        #windows_dict = windows.create_windows(flows)