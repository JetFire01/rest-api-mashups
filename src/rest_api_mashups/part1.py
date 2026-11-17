import json
import os
import time
import requests
from datetime import datetime
from pathlib import Path


BASE_URL = "http://10.194.69.214:3671"
SENSOR_PATH = "/api/v1/sensors/5/luminance"
DIMMER_PATH = "/api/v1/dimmers/7"
DIMMER_METHOD = "PUT"
DIMMER_PARAMETER = "value"

TARGET_LUX = 200
N_READINGS = 10
INTERVAL_S = 30
TIMEOUT_S = 10
LOG_FILE = Path(__file__).resolve().parents[2] / "logs" / "log_part1" / "light_log.json"


def extract_number(data):
    if isinstance(data, bool):
        return None
    if isinstance(data, (int, float)):
        return float(data)
    if isinstance(data, str):
        try:
            return float(data)
        except ValueError:
            return None
    if isinstance(data, dict):
        for key in ("luminance", "value", "lux", "state", "data"):
            if key in data:
                n = extract_number(data[key])
                if n is not None:
                    return n
        for v in data.values():
            n = extract_number(v)
            if n is not None:
                return n
    if isinstance(data, list):
        for v in data:
            n = extract_number(v)
            if n is not None:
                return n
    return None


def read_luminance():
    r = requests.get(BASE_URL + SENSOR_PATH, timeout=TIMEOUT_S)
    r.raise_for_status()
    try:
        data = r.json()
    except ValueError:
        data = r.text.strip()
    lux = extract_number(data)
    if lux is None:
        raise ValueError(f"Cannot find a luminance value in response: {r.text!r}")
    return lux


def compute_dimmer(lux):
    if lux >= TARGET_LUX:
        return 0
    value = round((TARGET_LUX - lux) / TARGET_LUX * 99)
    return max(0, min(99, value))


def set_dimmer(value):
    r = requests.request(DIMMER_METHOD, BASE_URL + DIMMER_PATH,
                         json={DIMMER_PARAMETER: value}, timeout=TIMEOUT_S)
    r.raise_for_status()
    return r.status_code


def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_log(entries):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)


def main():
    log = load_log()
    run_id = datetime.now().isoformat(timespec="seconds")
    for i in range(N_READINGS):
        entry = {"run": run_id, "reading": i + 1,
                 "datetime": datetime.now().isoformat(timespec="seconds")}
        try:
            lux = read_luminance()
            dimmer = compute_dimmer(lux)
            status = set_dimmer(dimmer)
            entry.update({"luminance": lux, "dimmer": dimmer, "dimmer_http_status": status})
            print(f"[{i + 1}/{N_READINGS}] {entry['datetime']}  lux={lux:.1f}  -> dimmer={dimmer}")
        except (requests.RequestException, ValueError) as e:
            entry["error"] = str(e)
            print(f"[{i + 1}/{N_READINGS}] ERROR: {e}")
        log.append(entry)
        save_log(log)  # save after every reading, so nothing is lost if interrupted
        if i < N_READINGS - 1:
            time.sleep(INTERVAL_S)
    try:
        set_dimmer(0)
        print("Dimmer switched off.")
    except requests.RequestException as e:
        print(f"Could not switch off the dimmer: {e}")
    print(f"Done. Log saved to {LOG_FILE}")


if __name__ == "__main__":
     main()