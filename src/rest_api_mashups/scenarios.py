from collections import Counter

USERS = {}       # {user_id: {"id", "first_name", "last_name", "email", "role", ...}}
BLOCKLIST = {}   # {ip: reason}
LOGINS = []      # [{"id", "user_id", "time", "ip", "status"}]
IP_INFO = {}     # {ip: reputation details from the API}


def load_data(users, blocklist, logins, ip_info):
    global USERS, BLOCKLIST, LOGINS, IP_INFO
    USERS, BLOCKLIST, LOGINS, IP_INFO = users, blocklist, logins, ip_info


# Other functions

def full_name(user):
    return f"{user['first_name']} {user['last_name']}"


# Login as a JSON dict, for the result file
def login_to_dict(login, show_user=False):
    item = {"time": str(login["time"]), "ip": login["ip"], "status": login["status"]}
    if show_user:
        user = USERS[login["user_id"]]
        item["user"] = full_name(user)
        item["role"] = user["role"]
    if login["ip"] in BLOCKLIST:
        item["blocklisted"] = BLOCKLIST[login["ip"]]
    return item


# User login report
def print_login(login, show_user=False):
    line = f"{login['time']}  {login['ip']:<15} {login['status']:<8}"
    if show_user:  # True in scenario 2 (IP investigation)
        user = USERS[login["user_id"]]
        line += f" {full_name(user)} ({user['role']})"
    if login["ip"] in BLOCKLIST:  # used in scenarios 1 and 2
        line += f"  [BLOCKLISTED: {BLOCKLIST[login['ip']]}]"
    print(line)


def find_user(query):
    if query.isdigit():
        return USERS.get(int(query))
    for user in USERS.values():
        if user["email"].lower() == query.lower():
            return user
    return None


# Scenarios

# Scenario 1 - login history of one user, with suspicious IPs flagged
def scenario_user_report(query):
    user = find_user(query)
    if user is None:
        print("User not found")
        return {"error": "user not found"}
    print(f"\n{full_name(user)} <{user['email']}>  role: {user['role']}")
    history = []
    for l in LOGINS:
        if l["user_id"] == user["id"]:
            history.append(l)

    result = {"user": {"id": user["id"], "name": full_name(user),
                       "email": user["email"], "role": user["role"]},
              "attempts": []}
    if not history:
        print(" No login attempts recorded")
        return result
    success_count = 0
    fail_count = 0
    risky = 0
    for login in history:
        print_login(login)
        result["attempts"].append(login_to_dict(login))
        if login["status"] == "success":
            success_count += 1
        else:
            fail_count += 1
        if login["ip"] in BLOCKLIST:
            risky += 1
    print(f"Total: {len(history)} | success: {success_count} | "
          f"fail: {fail_count} | from blocklisted IPs: {risky}")
    result["summary"] = {"total": len(history), "success": success_count,
                         "fail": fail_count, "from_blocklisted_ips": risky}
    return result


# Scenario 2 - everything known about one IP address
def scenario_ip_investigation(ip):
    if ip in BLOCKLIST:
        print(f"\nIP {ip}: BLOCKLISTED ({BLOCKLIST[ip]})")
    else:
        print(f"\nIP {ip}: not in blocklist")

    # New in TP2: what the reputation APIs say about this IP
    info = IP_INFO.get(ip)
    if info:
        isc = info["isc"]
        print(f"  SANS ISC : reports={isc.get('count')}  targets={isc.get('attacks')}  "
              f"feeds={', '.join(isc.get('feeds', [])) or '-'}")
        print(f"  GreyNoise: {info['greynoise'].get('classification')}"
              f" ({info['greynoise'].get('name') or '-'})")

    result = {"ip": ip, "blocklisted": ip in BLOCKLIST,
              "reason": BLOCKLIST.get(ip), "reputation": info, "attempts": []}

    from_ip = []
    for login in LOGINS:
        if login["ip"] == ip:
            from_ip.append(login)
    if not from_ip:
        print("  No login attempts from this IP")
        return result

    users = set()
    successes = 0
    for login in from_ip:
        print_login(login, show_user=True)
        result["attempts"].append(login_to_dict(login, show_user=True))
        users.add(login["user_id"])
        if login["status"] == "success":
            successes += 1
    print(f"Total: {len(from_ip)} attempts | {successes} successful | "
          f"{len(users)} different users")
    result["summary"] = {"total": len(from_ip), "success": successes,
                         "different_users": len(users)}
    return result


# Scenario 3 - successful logins from blocklisted IPs
def scenario_compromised(role=None):
    admins = []      # admins first, their compromise is the most critical
    others = []
    for login in LOGINS:
        if login["status"] != "success":
            continue                     # skip failed attempts
        if login["ip"] not in BLOCKLIST:
            continue                     # skip safe IPs
        user = USERS[login["user_id"]]
        if role is not None and user["role"] != role:
            continue                     # skip other roles if a filter is set
        if user["role"] == "admin":
            admins.append(login)
        else:
            others.append(login)
    hits = admins + others

    if role is None:
        print(f"\n{len(hits)} successful logins from blocklisted IPs:")
    else:
        print(f"\n{len(hits)} successful logins from blocklisted IPs (role: {role}):")
    result = {"role": role, "count": len(hits), "logins": []}
    for login in hits:
        user = USERS[login["user_id"]]
        print(f"[{user['role']:<9}] {full_name(user):<24} {user['email']:<38} "
              f"{login['ip']:<15} {BLOCKLIST[login['ip']]}")
        result["logins"].append({"role": user["role"], "user": full_name(user),
                                 "email": user["email"], "time": str(login["time"]),
                                 "ip": login["ip"], "reason": BLOCKLIST[login["ip"]]})
    return result


# Scenario 4 - users with many failed login attempts (possible password guessing)
def scenario_failed_logins(threshold):
    # Collect the failed attempts of each user: {user_id: [login, login, ...]}
    fails = {}
    for login in LOGINS:
        if login["status"] != "fail":
            continue
        if login["user_id"] not in fails:
            fails[login["user_id"]] = []
        fails[login["user_id"]].append(login)

    result = {"threshold": threshold, "users": []}
    for user_id in USERS:                # go through users in id order
        if user_id not in fails:
            continue                     # no failed attempt at all
        user_fails = fails[user_id]
        if len(user_fails) < threshold:
            continue                     # not enough failures
        user = USERS[user_id]
        print(f"\n{full_name(user)} ({user['role']}): {len(user_fails)} failed attempts")

        bad_ips = []                     # blocklisted IPs used, without duplicates
        for login in user_fails:
            if login["ip"] in BLOCKLIST and login["ip"] not in bad_ips:
                bad_ips.append(login["ip"])
        for ip in bad_ips:
            print(f"  from {ip} [BLOCKLISTED: {BLOCKLIST[ip]}]")
        result["users"].append({"user": full_name(user), "role": user["role"],
                                "failed_attempts": len(user_fails),
                                "blocklisted_ips": [{"ip": ip, "reason": BLOCKLIST[ip]}
                                                    for ip in bad_ips]})

    if not result["users"]:
        print(f"\nNo user with {threshold} or more failed attempts.")
    return result


# Scenario 5 - statistics over a period: success/fail, threats by type, top users, inactive accounts
def scenario_period_stats(start, end, role=None):
    period = []
    for login in LOGINS:
        if login["time"] < start or login["time"] > end:
            continue                     # outside the period
        if role is not None and USERS[login["user_id"]]["role"] != role:
            continue                     # other role
        period.append(login)

    if role is None:
        print(f"\nPeriod {start.date()} -> {end.date()}")
    else:
        print(f"\nPeriod {start.date()} -> {end.date()}, role: {role}")
    result = {"start": str(start.date()), "end": str(end.date()), "role": role}
    if not period:
        print("  No login attempts in this period")
        result["attempts"] = 0
        return result

    success_count = 0
    fail_count = 0
    threats = Counter()          # {reason: number of attempts}
    per_user = Counter()         # {user_id: number of attempts}
    active = set()               # ids of users who tried to log in
    for login in period:
        if login["status"] == "success":
            success_count += 1
        else:
            fail_count += 1
        if login["ip"] in BLOCKLIST:
            threats[BLOCKLIST[login["ip"]]] += 1
        per_user[login["user_id"]] += 1
        active.add(login["user_id"])

    print(f"Attempts: {len(period)} | success: {success_count} | "
          f"fail: {fail_count} ({fail_count / len(period):.0%})")

    print("Attempts from blocklisted IPs by reason:")
    for reason, count in threats.most_common():
        print(f"  {count:>4}  {reason}")

    print("Top 5 most active users:")
    for user_id, count in per_user.most_common(5):
        print(f"  {full_name(USERS[user_id]):<28} {count} attempts")

    inactive = []
    for user in USERS.values():
        if user["id"] in active:
            continue                     # this user was active
        if role is not None and user["role"] != role:
            continue                     # other role
        inactive.append(user)
    print(f"Inactive accounts (no attempt in this period): {len(inactive)}")
    for user in inactive:
        print(f"  #{user['id']:<4} {full_name(user):<28} {user['role']}")

    result.update({
        "attempts": len(period), "success": success_count, "fail": fail_count,
        "fail_rate": round(fail_count / len(period), 2),
        "blocklisted_by_reason": dict(threats.most_common()),
        "top_users": [{"user": full_name(USERS[uid]), "attempts": c}
                      for uid, c in per_user.most_common(5)],
        "inactive_accounts": [{"id": u["id"], "user": full_name(u), "role": u["role"]}
                              for u in inactive],
    })
    return result