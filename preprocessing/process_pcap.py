# we are going to get the pcap info from the file into python
# using pyshark or scapy or tshark (linux?)
# we can filter for specific protocols with this

# iterate over every row, inserting them into the database

import os
import subprocess
import sys
import re
import tshark

# devnull = file that discards all written to it, used to despose of unwanted output streams
# with open(os.devnull, "w") as null:
#   version_output = subprocess.check_output(parameters, stderr=null).decode("ascii")

# template for tshark functions
def get_tshark_version():
    parameters = [tshark.get_process_path(), "-v"]
    with open(os.devnull, "w") as null:
        version_output = subprocess.check_output(parameters, stderr=null).decode("ascii")

