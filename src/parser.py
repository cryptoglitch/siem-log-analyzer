import csv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "logs" / "security_log.csv"


def load_logs():
    events = []

    with open(LOG_FILE, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            events.append(row)

    return events