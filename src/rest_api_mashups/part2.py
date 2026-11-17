import json
import sys
import requests
import scenarios
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
CACHE_FILE = DATA_DIR / "ip_cache.json"
RESULTS_FILE = ROOT / "logs" / "log_part2" / "results.json"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
TIMEOUT = 15
# SANS ISC asks for a custom User-Agent (default python ones may be blocked)
HEADERS = {"User-Agent": "rest-api-mashups (student project, University of Geneva)"}
N_USERS = 100   # our login logs use user 1..100


# API 1: DummyJSON, user accounts
def load_users():
    r = requests.get("https://dummyjson.com/users",
                     params={"limit": N_USERS, "select": "firstName,lastName,email,role"},
                     timeout=TIMEOUT)
    r.raise_for_status()
    users = {}
    for u in r.json()["users"]:
        users[u["id"]] = {"id": u["id"], "first_name": u["firstName"],
                          "last_name": u["lastName"], "email": u["email"], "role": u["role"]}
    return users


# API 2: SANS Internet Storm Center, reputation of one IP
def ask_isc(ip):
    r = requests.get(f"https://isc.sans.edu/api/ip/{ip}?json",
                     headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json().get("ip", {})
    feeds = data.get("threatfeeds") or {}
    return {"count": data.get("count"), "attacks": data.get("attacks"),
            "feeds": sorted(feeds) if isinstance(feeds, dict) else []}


# API 3: GreyNoise Community, classification of one IP
def ask_greynoise(ip):
    r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=TIMEOUT)
    if r.status_code == 404:              # IP never seen scanning the internet
        return {"classification": "not observed", "name": None}
    if r.status_code == 429:              # daily limit reached (more 50 lookups)
        raise RuntimeError("GreyNoise daily limit reached")
    r.raise_for_status()
    data = r.json()
    return {"classification": data.get("classification"), "name": data.get("name")}


# Reputation of every IP, from the cache or from the API

def load_ip_info(ips, refresh=False):
    cache = {}
    if CACHE_FILE.exists() and not refresh:
        with open(CACHE_FILE, encoding="utf-8") as f:
            cache = json.load(f)

    for ip in sorted(ips):
        if ip in cache:
            continue
        print(f"  checking {ip} ...")
        try:
            cache[ip] = {"isc": ask_isc(ip), "greynoise": ask_greynoise(ip),
                         "checked": datetime.now().strftime(TIME_FORMAT)}
        except (requests.RequestException, RuntimeError, ValueError) as e:
            print(f"  ! could not check {ip}: {e}")   # not cached: will be retried next run

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=4)
    return cache


 # Replaces blocklist.json of TP1 for every suspicious IP

def build_blocklist(ip_info):
    blocklist = {}
    for ip, info in ip_info.items():
        reasons = []
        if info["isc"]["count"]:
            reasons.append("ISC attack reports")
        if info["isc"]["feeds"]:
            reasons.append("feeds: " + ", ".join(info["isc"]["feeds"]))
        if info["greynoise"]["classification"] == "malicious":
            reasons.append("GreyNoise malicious")
        if reasons:
            blocklist[ip] = "; ".join(reasons)
    return blocklist


# Data loading (local file)

def load_logins():
    with open(DATA_DIR / "logins.json", encoding="utf-8") as f:
        data = json.load(f)
    logins = []
    for item in data:
        logins.append({"id": item["id"], "user_id": item["user_id"],
                       "time": datetime.strptime(item["timestamp"], TIME_FORMAT),
                       "ip": item["ip"], "status": item["status"]})
    logins.sort(key=lambda login: login["time"])  # chronological order
    return logins


# Results file

def save_result(scenario, user_input, result):
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    results = []
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
    results.append({"datetime": datetime.now().strftime(TIME_FORMAT),
                    "scenario": scenario, "input": user_input, "result": result})
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n(result added to {RESULTS_FILE.relative_to(ROOT)})")


# Menu

def ask_role():
    print("   Hint: admin, moderator or user. Press Enter to include all roles.")
    role = input("Filter by role (admin/moderator/user, empty = all): ").strip().lower()
    if role == "":
        return None              # nothing typed = no filter
    return role


def ask_date(prompt):
    while True:
        try:
            return datetime.strptime(input(prompt).strip(), "%Y-%m-%d")
        except ValueError:
            print("Format: YYYY-MM-DD")


MENU = """
    Auth log analysis (TP2: remote APIs)
    
1. User report (by id or email)
2. IP investigation
3. Successful logins from blocklisted IPs
4. Users with many failed logins
5. Statistics over a period
0. Quit"""


def main():
    print("Loading data...")
    users = load_users()
    logins = load_logins()
    ip_info = load_ip_info({login["ip"] for login in logins}, refresh="--refresh" in sys.argv)
    blocklist = build_blocklist(ip_info)
    scenarios.load_data(users, blocklist, logins, ip_info)
    print(f"Loaded {len(users)} users (DummyJSON), {len(logins)} logins (local), "
          f"{len(ip_info)} IPs checked (SANS ISC + GreyNoise), {len(blocklist)} suspicious")

    while True:
        print(MENU)
        choice = input("Choice: ").strip()
        if choice == "1":
            print(f"  Hint: an id from {min(users)} to {max(users)} (e.g. 7), "
                  f"or an email (e.g. {users[1]['email']})")
            query = input("User id or email: ").strip()
            save_result("user report", {"query": query}, scenarios.scenario_user_report(query))
        elif choice == "2":
            normal_ip = next((l["ip"] for l in logins if l["ip"] not in blocklist), None)
            print(f"  Hint: suspicious IPs, e.g. {', '.join(list(blocklist)[:2])}; "
                  f"a normal IP, e.g. {normal_ip}")
            ip = input("IP address: ").strip()
            save_result("ip investigation", {"ip": ip}, scenarios.scenario_ip_investigation(ip))
        elif choice == "3":
            role = ask_role()
            save_result("compromised accounts", {"role": role}, scenarios.scenario_compromised(role))
        elif choice == "4":
            print("  Hint: a number, e.g. 8 or 10. Press Enter for 8")
            value = input("Minimum failed attempts [8]: ").strip()
            threshold = int(value) if value.isdigit() else 8
            save_result("failed logins", {"threshold": threshold},
                        scenarios.scenario_failed_logins(threshold))
        elif choice == "5":
            print(f"  Hint: the logs go from {logins[0]['time'].date()} to "
                  f"{logins[-1]['time'].date()}, e.g. 2026-09-01 then 2026-09-30")
            start = ask_date("Start date (YYYY-MM-DD): ")
            end = ask_date("End date (YYYY-MM-DD): ").replace(hour=23, minute=59, second=59)
            role = ask_role()
            save_result("period statistics",
                        {"start": str(start.date()), "end": str(end.date()), "role": role},
                        scenarios.scenario_period_stats(start, end, role))
        elif choice == "0":
            break
        else:
            print("Unknown choice")


if __name__ == "__main__":
    main()