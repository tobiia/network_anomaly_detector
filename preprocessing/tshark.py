import os
import subprocess
import sys
import re

# pyshark
def get_process_path(process_name="tshark"):
    possible_paths = []

    # windows
    if sys.platform.startswith("win"):
        for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
            program_files = os.getenv(env)
            if program_files is not None:
                possible_paths.append(
                    os.path.join(program_files, "Wireshark", f"{process_name}.exe")
                )
    # mac
    elif sys.platform.startswith("darwin"):
        possible_paths.append(f"/Applications/Wireshark.app/Contents/MacOS/{process_name}")
    # linux
    else:
        os_path = os.getenv(
            "PATH",
            "/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin"
        )
        for path in os_path.split(":"):
            possible_paths.append(os.path.join(path, process_name))

    for path in possible_paths:
        if os.path.exists(path):
            if sys.platform.startswith("win"):
                path = path.replace("\\", "/")
            return path
        
# devnull = file that discards all written to it, used to despose of unwanted output streams
# with open(os.devnull, "w") as null:
#   version_output = subprocess.check_output(parameters, stderr=null).decode("ascii")

def call_tshark(arg):
    parameters = [get_process_path(), arg]
    with open(os.devnull, "w") as null:
        output = subprocess.check_output(parameters, stderr=null)

# open pcap in tshark

# open pcap in tshark with specific filters
def load_pcap(path):

    "tshark -r ./data/botnet.pcap -Y 'http and frame.number == 171' -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len -e http.accept -e http.accept_encoding -e http.authorization -e http.cache_control -e http.connection -e http.cookie -e http.content_length -e http.content_type -e http.date -e http.host -e http.request.method -e tcp.srcport -e tcp.dstport -e http.proxy_authorization -e http.request.uri"

    "tshark -r ./data/botnet.pcap -Y 'tcp and frame.number == 254' -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.srcport -e tcp.dstport -e tcp.flags.ack -e tcp.flags.syn"

    "tshark -r ./data/botnet.pcap -Y 'dns and frame.number == 259' -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e frame.len -e dns.qry.name -e dns.qry.type -e udp.srcport -e udp.dstport"
    parameters = [get_process_path(), ]

# convert pcap into iterable object (list of JSON)
