# rest-api-mashups — TP2: Using existing APIs

**Structure of project**
```
rest-api-mashups/
├── data/
│   ├── logins.json            # local login logs (Part 2)
│   └── ip_cache.json          # cached answers of the IP reputation API (Part 2)
├── logs/
│   ├── log_part1/             # luminance / dimmer logs (Part 1)
│   └── log_part2/results.json # scenario inputs and results (Part 2)
└── src/rest_api_mashups/
    ├── part1.py               # Part 1: light regulation
    ├── part2.py               # Part 2: API loading, cache, menu, result file
    └── scenarios.py           # Part 2: the 5 scenarios reused from TP1
```

Requirements: Python 3.10+, `pip install -r requirements.txt` (only `requests`).

---

## Part 1 — Light regulation with the room's REST API

**Run:** `python3 src/rest_api_mashups/part1.py`

### APIs
The API at `http://10.194.69.214:3671`:

| Action         | Request |
|----------------|---|
| Read luminance | `GET /api/v1/sensors/5/luminance` |
| Set the dimmer | `PUT /api/v1/dimmers/7` |

### What the program does
10 times, every 30 seconds: read the luminance, compute the dimmer value, send it to the dimmer, and append
date/time, luminance and dimmer value to `logs/log_part1/light_log.json`. After the 10th reading the dimmer is switched off.

```
luminance >= 200  ->  dimmer = 0
luminance <  200  ->  dimmer = round((200 - luminance) / 200 * 99)
```

### Measurements

| Run | Log file | Date / time | Conditions | Luminance (lux) | Dimmer |
|-----|---|---|---|---|---|
| 1   | `light_log_1.json` | 2026-11-14 18:24 | night | 0 | 99 |
| 2   | `light_log_2.json` | 2026-11-15 10:24 | morning | 634 – 774 | 0 |
| 3   | `light_log_3.json` | 2026-11-15 11:08 | late morning | 537 – 712 | 0 |
| 4   | `light_log_4.json` | 2026-11-15 15:06 | afternoon | 591 – 664 | 0 |
| 5   | `light_log_5.json` | 2026-11-15 17:04 | dusk | 7 – 16 | 91 – 96 |

During the day the natural light is above 200 lux, so the dimmer stays off. At dusk the luminance falls to 7–16 lux and the
dimmer is set to 91–96, following the formula (e.g. 11 lux → round(189 / 200 × 99) = 94). At night it is fully on (99).

---

## Part 2 — Mashup of remote APIs

**Run:** `python3 src/rest_api_mashups/part2.py` (add `--refresh` to ask the IP reputation APIs again instead of using the cache).

The scenarios of TP1 (analysis of login logs to detect suspicious activity) are reused. In TP1 the data came from three local files,
here two of them are replaced by remote APIs:

| TP1 file | TP2 source | Data used |
|---|---|---|
| `users.json` | **DummyJSON** — `GET https://dummyjson.com/users?limit=100` | id, name, email, role (`admin` / `moderator` / `user`) |
| `blocklist.json` | **SANS Internet Storm Center** — `GET https://isc.sans.edu/api/ip/{ip}?json` | number of attack reports, threat feeds the IP appears in |
| | **GreyNoise Community** — `GET https://api.greynoise.io/v3/community/{ip}` | classification: `malicious` / `benign` / `unknown` / not observed |
| `logins.xml` | `data/logins.json` (local) | login attempts: user id, time, IP, success/fail |

All three APIs are free and need no API key. SANS ISC asks for a custom `User-Agent`. GreyNoise allows about 50 lookups/day without a key,
so each IP is checked only once and the answers are cached in `data/ip_cache.json`.

### Why the login logs stay local
Login logs are private data of a given system, no public API provides them. The file was generated with Mockaroo
(1000 attempts, Jan–Nov 2026, users 1–100). Its IP addresses are real: 10 of them are among the most active attacking IPs
reported by SANS ISC (`/api/sources/attacks/20`).

### How the data is combined
```
logins.json ──user_id──► DummyJSON          (who is the user, which role)
     └──────────ip─────► SANS ISC + GreyNoise (is the IP suspicious, and why)
```
An IP is considered **suspicious** if at least one source reports it: ISC has attack reports for it, or it appears in an ISC threat
feed, or GreyNoise classifies it as malicious. The reasons are kept (e.g. `feeds: ciarmy; GreyNoise malicious`) and replace the
`reason` field of TP1's blocklist. Result: 11 of the 25 IPs are suspicious, including one "home" address (`62.202.180.71`) that
appears in the *blocklist.de SSH* and *compromised hosts* feeds.

### Scenarios (from TP1)
1. **User report** (id or email) — the user's login history, suspicious IPs flagged.
2. **IP investigation** (IP) — what ISC and GreyNoise say about the IP, and which users logged in from it.
3. **Successful logins from suspicious IPs** (optional role) — possibly compromised accounts, admins first.
4. **Users with many failed logins** (threshold) — possible password guessing, with the suspicious IPs involved.
5. **Statistics over a period** (dates, optional role) — success/fail, threats by reason, top users, inactive accounts.


### Results
`logs/log_part2/results.json` contains 10 runs, 2 per scenario with different inputs
(user by id and by email, a suspicious and a clean IP, role filters, two thresholds, two periods).