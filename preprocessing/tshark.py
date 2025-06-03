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