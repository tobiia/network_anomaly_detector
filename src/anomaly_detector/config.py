from pathlib import Path
from dataclasses import dataclass

@dataclass
class Config:
    PROJECT_ROOT = Path(__file__).parent.parent
    # CONFIG_DIR = PROJECT_ROOT / "config"
    # SETTINGS_FILE = CONFIG_DIR / "settings.json"
    GUI_DIR = PROJECT_ROOT / "gui"
    NOTEBOOK_DIR = PROJECT_ROOT / "notebooks"
    RUN_DIR = PROJECT_ROOT / "runs"
    SETUP_DIR = PROJECT_ROOT / "setup"