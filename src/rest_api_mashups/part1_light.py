"""
TP2 - Part 1: regulate a light bulb from the ambient luminance sensor.

Usage:
    python part1_light.py            # 10 readings, every 30 s
    python part1_light.py --discover # print what the API root returns (to find the endpoints)

!! Check the 3 constants below (SENSOR_PATH, BULB_PATH, BULB_METHOD) against the
   real API before running. The slides do not give the endpoint names.
"""
import json
import os
import sys
import time
from datetime import datetime

import requests

BASE_URL = "http://10.194.69.214:3671"
SENSOR_PATH = "/api/v1/sensors/5/luminance"
BULB_PATH = "/api/v1/dimmers/7"
BULB_METHOD = "PUT"
BULB_FIELD = "value"

TARGET_LUX = 200
N_READINGS = 10
INTERVAL_S = 30
LOG_FILE = "light_log.json"
TIMEOUT_S = 10


def extract_number(data):
    """Return the first numeric value found in a JSON response (int, float or nested dict/list)."""
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


def compute_bulb(lux):
    if lux >= TARGET_LUX:
        return 0
    value = round((TARGET_LUX - lux) / TARGET_LUX * 99)
    return max(0, min(99, value))  # stay inside the bulb range 0-99


def set_bulb(value):
    r = requests.request(BULB_METHOD, BASE_URL + BULB_PATH,
                         json={BULB_FIELD: value}, timeout=TIMEOUT_S)
    r.raise_for_status()
    return r.status_code


def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_log(entries):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)


def discover():
    for path in ("/", "/api", "/sensors", "/devices"):
        try:
            r = requests.get(BASE_URL + path, timeout=TIMEOUT_S)
            print(f"GET {path} -> {r.status_code}\n{r.text[:1000]}\n")
        except requests.RequestException as e:
            print(f"GET {path} -> error: {e}\n")


def main():
    log = load_log()
    run_id = datetime.now().isoformat(timespec="seconds")
    for i in range(N_READINGS):
        entry = {"run": run_id, "reading": i + 1,
                 "datetime": datetime.now().isoformat(timespec="seconds")}
        try:
            lux = read_luminance()
            bulb = compute_bulb(lux)
            status = set_bulb(bulb)
            entry.update({"luminance": lux, "bulb": bulb, "bulb_http_status": status})
            print(f"[{i + 1}/{N_READINGS}] {entry['datetime']}  lux={lux:.1f}  -> bulb={bulb}")
        except (requests.RequestException, ValueError) as e:
            entry["error"] = str(e)
            print(f"[{i + 1}/{N_READINGS}] ERROR: {e}")
        log.append(entry)
        save_log(log)  # save after every reading, so nothing is lost if interrupted
        if i < N_READINGS - 1:
            time.sleep(INTERVAL_S)
    try:
        set_bulb(0)
        print("Bulb switched off.")
    except requests.RequestException as e:
        print(f"Could not switch off the bulb: {e}")
    print(f"Done. Log saved to {LOG_FILE}")


if __name__ == "__main__":
    if "--discover" in sys.argv:
        discover()
    else:
        main()
