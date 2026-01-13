from pathlib import Path
from dataclasses import dataclass

@dataclass
class Config:
    PROJECT_ROOT = Path(__file__).parent
    # CONFIG_DIR = PROJECT_ROOT / "config"
    # SETTINGS_FILE = CONFIG_DIR / "settings.json"
    GUI_DIR = PROJECT_ROOT / "gui"
    MODEL_DIR = PROJECT_ROOT / "models"
    RUNS_DIR = PROJECT_ROOT / "runs"
    SETUP_DIR = PROJECT_ROOT / "setup"
    
    # REVIEW delete this once file dialog done
    PCAP_PATH = Path.home() / "network_detect" / "data" / "infected.pcap"
    LOG_PATH = Path.home() / "network_detect" / "src" / "network_detect" / "runs" / "280126_030631"