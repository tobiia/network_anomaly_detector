from setup import zeek
from pathlib import Path

def main():
    # file dialog to get pcap
    pcap_path = Path(pcap_path).resolve()
    zeek.process_pcap(pcap_path)


if __name__ == "__main__":
    main()