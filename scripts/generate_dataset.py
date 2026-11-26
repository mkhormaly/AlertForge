#!/usr/bin/env python3
"""
AlertForge evaluation dataset v1 generator.

Run ONCE, commit the three output files, and never regenerate: the point of a frozen test set is
that the rules are measured against data that was fixed before they were tuned.

Outputs (under data/eval/):
  dataset-v1.log           web access log, combined format, chronological
  dataset-v1-labels.csv    one row per log line with the expected outcome
  dataset-v1-manifest.txt  counts and SHA-256 hashes (the evaluation runner verifies them)

Inputs: data/eval/payloads/sqli.txt and xss.txt, produced by scripts/select_payloads.py
from public SecLists payload lists.

Design rules that keep the evaluation honest:
  * every episode (attack, look-alike or background user) has its OWN source IP, so alerts can be
    mapped to episodes by IP alone;
  * attack payloads come from public lists, not from our rules;
  * look-alike normal cases are written without looking at the rules' regular expressions.

Needs only the Python 3 standard library.
"""
import csv
import hashlib
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

SEED = 20261125
TZ = timezone(timedelta(hours=3))
START = datetime(2026, 11, 16, 9, 0, 0, tzinfo=TZ)
WINDOW_SECONDS = 2 * 3600

N_USERS = 40
REQUESTS_PER_USER = 75
N_PER_SCENARIO = 30

OUT_DIR = Path("data/eval")
PAYLOAD_DIR = OUT_DIR / "payloads"
PREFIX = OUT_DIR / "dataset-v1"

# Explicit month names: strftime("%b") depends on the operating-system language
# (a Turkish Windows would write "Kas" instead of "Nov") and would break the parser.
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

# --- attacker tooling -------------------------------------------------------------------------
BRUTE_FORCE_UAS = ["python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1",
                   "Mozilla/4.0 (Hydra)", "Python-urllib/3.11"]

VULN_SCANNERS = [
    ("sqlmap", "sqlmap/1.7.2#stable (https://sqlmap.org)"),
    ("nikto", "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"),
    ("nmap-nse", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"),
    ("nuclei", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"),
    ("wpscan", "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"),
    ("openvas", "Mozilla/5.0 [en] (X11, U; OpenVAS-VT)"),
]
VULN_SCANNER_PATHS = ["/", "/robots.txt", "/ftp/", "/.git/config", "/.env", "/administrator/",
                      "/phpmyadmin/", "/wp-login.php", "/server-status", "/api/Users",
                      "/rest/admin/application-version", "/rest/products/search?q=test"]

DIR_SCANNERS = [
    ("gobuster", "gobuster/3.6"),
    ("ffuf", "Fuzz Faster U Fool v2.1.0"),
    ("feroxbuster", "feroxbuster/2.10.4"),
    ("wfuzz", "Wfuzz/3.1.0"),
    ("dirbuster", "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"),
]
WORDLIST_PATHS = ["admin", "backup", "login", "config", "uploads", "old", "test", "dev", "api",
                  "private", "secret", "tmp", "logs", "db", "download", "files", "staging",
                  "internal", "console", "manager", "portal", "dashboard", "temp", "archive"]

ENUM_RESOURCES = [("api", "Products"), ("api", "Users"), ("api", "Feedbacks"),
                  ("rest", "basket"), ("api", "Cards")]

# --- look-alike benign traffic ----------------------------------------------------------------
BENIGN_SQL_LIKE = [
    "O'Brien Irish pub", "select a gift card", "union jack flag", "drop shipping guide",
    "order by newest", "it's a wonderful life", "AT&T phone charger", "5 - 3 = 2 maths puzzle",
    "women's running shoes", "Guns N' Roses poster", "rock & roll t-shirt", "kids' toys",
    "delete account help", "update my address", "table and chairs set", "insert coin arcade game",
    "create a gift list", "executive desk chair", "like new condition", "where to buy apples",
    "sleep mask silk", "cats and dogs calendar", "salt or pepper grinder", "1 or 2 person tent",
    "grill; bbq tools", "# 1 mom mug", "50% off sale", "d'Artagnan novel", "mac & cheese maker",
    "x-ray vision glasses",
]
BENIGN_XSS_LIKE = [
    "script writing for beginners", "javascript the good parts book", "onion rings recipe",
    "alert bracelet medical", "iframe photo frame", "svg icon pack", "img2pdf tool",
    "<3 love mug", "a < b maths poster", "x > y t-shirt", "document holder desk",
    "cookie jar ceramic", "embed tool kit", "object lens cleaner", "onclick ballpoint pen",
    "on-ear headphones", "body lotion", "style guide book", "input device cleaner",
    "form fitting jacket", "html and css book", "web developer hoodie", "tote bag with link print",
    "ear plugs for sleep", "window cleaner spray", "alert dog collar", "event planner notebook",
    "load bearing shelf", "mouse over-ear pad", "error 404 poster",
]
BENIGN_TOOLS = [
    ("googlebot", "Googlebot/2.1 (+http://www.google.com/bot.html)"),
    ("bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("uptimerobot", "UptimeRobot/2.0 (+http://www.uptimerobot.com/)"),
    ("curl", "curl/8.4.0"),
    ("python-urllib", "Python-urllib/3.11"),
    ("ahrefsbot", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"),
    ("postman", "PostmanRuntime/7.36.0"),
    ("go-http-client", "Go-http-client/2.0"),
    ("java-client", "Java/17.0.9"),
    ("wget", "Wget/1.21.4"),
]
BENIGN_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/rest/products/search?q=", "/ftp/legal.md",
                "/api/Challenges/?name=Score%20Board", "/rest/user/whoami"]

SEARCH_WORDS = ["apple juice", "banana", "lemon", "orange", "raspberry", "carrot", "melon",
                "eggfruit", "kiwi", "apple pomace", "juice", "green smoothie", "gift", "t-shirt",
                "mug", "stickers", "hoodie", "best seller", "vegan", "fruit basket", "carrot juice"]
IMAGES = ["apple_juice", "banana_juice", "carrot_juice", "eggfruit_juice", "fruit_press",
          "green_smoothie", "lemon_juice", "melon_bike", "raspberry_juice", "strawberry_juice"]


def log_time(ts):
    return "%02d/%s/%d:%02d:%02d:%02d %s" % (ts.day, MONTHS[ts.month - 1], ts.year, ts.hour,
                                             ts.minute, ts.second, ts.strftime("%z"))


def read_payloads(name):
    path = PAYLOAD_DIR / (name + ".txt")
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(lines) < N_PER_SCENARIO:
        sys.exit("%s needs at least %d payloads, found %d" % (path, N_PER_SCENARIO, len(lines)))
    return lines[:N_PER_SCENARIO]


def wire(payload):
    # percent-encode like a client would; an existing %XX sequence is kept as it is
    return quote(payload, safe="%")


class Builder:
    def __init__(self, rnd):
        self.r = rnd
        self.events = []     # (time, seq, ip, method, target, status, size, ua, episode_id)
        self.episodes = {}   # episode_id -> dict
        self.seq = 0
        self.counters = {"user": 0, "look": 0, "attack": 0}

    def new_ip(self, kind):
        i = self.counters[kind]
        self.counters[kind] += 1
        if kind == "user":
            return "192.168.10.%d" % (11 + i)
        if kind == "look":
            return "192.168.20.%d" % (1 + i)
        return "10.20.%d.%d" % (i // 250, i % 250 + 1)

    def episode(self, ep_id, kind, scenario, variant, attack, expected_rule):
        ip = self.new_ip(kind)
        self.episodes[ep_id] = {"ip": ip, "scenario": scenario, "variant": variant,
                                "attack": attack, "expected_rule": expected_rule}
        return ip

    def add(self, ep_id, t, method, target, status, size, ua):
        self.seq += 1
        self.events.append((t, self.seq, self.episodes[ep_id]["ip"], method, target,
                            status, size, ua, ep_id))

    def start(self):
        return START + timedelta(seconds=self.r.uniform(0, WINDOW_SECONDS))

    def browser(self):
        return self.r.choice(BROWSERS)


def build_background(b):
    r = b.r
    for u in range(N_USERS):
        ep = "bg-%03d" % (u + 1)
        b.episode(ep, "user", "background", "normal_user", False, "")
        ua = b.browser()
        t = START + timedelta(seconds=r.uniform(0, 5400))
        basket_id = r.randint(1, 8)
        typo = u % 10 == 0  # 4 users mistype their password once
        fixed = [("GET", "/", 200, 1950), ("GET", "/main.js", 200, 480000),
                 ("GET", "/runtime.js", 200, 3200), ("GET", "/polyfills.js", 200, 12000),
                 ("GET", "/styles.css", 200, 25000)]
        n_special = 1 + (1 if typo else 0)
        n_random = REQUESTS_PER_USER - len(fixed) - n_special
        kinds = r.choices(["search", "product", "image", "whoami", "challenges", "basket", "socket"],
                          weights=[30, 25, 15, 8, 5, 7, 10], k=n_random)
        login_at = r.randint(2, n_random)
        seq = list(fixed)
        for i, kind in enumerate(kinds):
            if i == login_at:
                if typo:
                    seq.append(("POST", "/rest/user/login", 401, 26))
                seq.append(("POST", "/rest/user/login", 200, 831))
            if kind == "search":
                seq.append(("GET", "/rest/products/search?q=" + quote(r.choice(SEARCH_WORDS), safe=""),
                            200, r.randint(1500, 6000)))
            elif kind == "product":
                seq.append(("GET", "/api/Products/%d" % r.randint(1, 40), 200, r.randint(300, 900)))
            elif kind == "image":
                seq.append(("GET", "/assets/public/images/products/%s.jpg" % r.choice(IMAGES), 200,
                            r.randint(20000, 90000)))
            elif kind == "whoami":
                seq.append(("GET", "/rest/user/whoami", 200, 11))
            elif kind == "challenges":
                seq.append(("GET", "/api/Challenges/?name=Score%20Board", 200, 640))
            elif kind == "basket":
                seq.append(("GET", "/rest/basket/%d" % basket_id, 200, r.randint(200, 700)))
            else:
                seq.append(("GET", "/socket.io/?EIO=4&transport=polling&t=%06x" % r.randint(0, 0xFFFFFF),
                            200, 98))
        if login_at >= len(kinds):  # safety: login position past the end
            seq.append(("POST", "/rest/user/login", 200, 831))
        assert len(seq) == REQUESTS_PER_USER, (len(seq), typo)
        for method, target, status, size in seq:
            t += timedelta(seconds=max(1.5, r.expovariate(1 / 40.0)))
            if status == 200 and r.random() < 0.03:
                status = 304
            b.add(ep, t, method, target, status, size, ua)


def build_brute_force(b):
    r = b.r
    tempos = ["fast"] * 20 + ["medium"] * 5 + ["slow"] * 5
    for i, tempo in enumerate(tempos):
        ep = "bf-%03d" % (i + 1)
        b.episode(ep, "attack", "brute_force", tempo, True, "AF-001")
        ua = r.choice(BRUTE_FORCE_UAS)
        t = b.start()
        for _ in range(r.randint(8, 12)):
            b.add(ep, t, "POST", "/rest/user/login", 401, 26, ua)
            gap = {"fast": r.uniform(0.5, 3.0), "medium": r.uniform(4.0, 11.0),
                   "slow": r.uniform(20.0, 30.0)}[tempo]
            t += timedelta(seconds=gap)


def build_vuln_scanner(b):
    r = b.r
    for i in range(N_PER_SCENARIO):
        name, tool = VULN_SCANNERS[i % len(VULN_SCANNERS)]
        ep = "vs-%03d" % (i + 1)
        b.episode(ep, "attack", "vuln_scanner", name, True, "AF-002")
        t = b.start()
        for _ in range(r.randint(5, 12)):
            path = r.choice(VULN_SCANNER_PATHS)
            b.add(ep, t, "GET", path, r.choice([200, 404, 404, 403]), r.randint(150, 4000), tool)
            t += timedelta(seconds=r.uniform(0.2, 2.0))


def build_dir_scanner(b):
    r = b.r
    for i in range(N_PER_SCENARIO):
        name, tool = DIR_SCANNERS[i % len(DIR_SCANNERS)]
        ep = "ds-%03d" % (i + 1)
        b.episode(ep, "attack", "dir_scanner", name, True, "AF-006")
        t = b.start()
        for _ in range(r.randint(8, 20)):
            b.add(ep, t, "GET", "/" + r.choice(WORDLIST_PATHS), r.choice([404, 404, 404, 200, 301]),
                  r.randint(100, 800), tool)
            t += timedelta(seconds=r.uniform(0.05, 0.5))


def build_injection(b, prefix, scenario, rule, payloads):
    r = b.r
    for i, payload in enumerate(payloads):
        ep = "%s-%03d" % (prefix, i + 1)
        b.episode(ep, "attack", scenario, "single_request", True, rule)
        b.add(ep, b.start(), "GET", "/rest/products/search?q=" + wire(payload),
              r.choice([200, 200, 500]) if scenario == "sqli" else 200,
              r.randint(100, 4000), b.browser())


def build_id_enum(b):
    r = b.r
    tempos = ["fast"] * 20 + ["medium"] * 5 + ["slow"] * 5
    for i, tempo in enumerate(tempos):
        ep = "ie-%03d" % (i + 1)
        b.episode(ep, "attack", "id_enum", tempo, True, "AF-005")
        area, resource = r.choice(ENUM_RESOURCES)
        first = r.randint(1, 30)
        t = b.start()
        for k in range(r.randint(20, 40)):
            n = first + k
            b.add(ep, t, "GET", "/%s/%s/%d" % (area, resource, n), 200 if n <= 35 else 404,
                  r.randint(200, 700), "python-requests/2.31.0")
            gap = {"fast": r.uniform(0.3, 1.4), "medium": r.uniform(1.6, 1.9),
                   "slow": r.uniform(3.0, 5.0)}[tempo]
            t += timedelta(seconds=gap)


def build_lookalikes(b):
    r = b.r
    # brute force: typos, four failures, failures spread out
    variants = ["few_typos"] * 10 + ["four_failures"] * 10 + ["spread_out"] * 10
    for i, variant in enumerate(variants):
        ep = "lk-bf-%03d" % (i + 1)
        b.episode(ep, "look", "lookalike_brute_force", variant, False, "")
        ua = b.browser()
        t = b.start()
        n_fail = {"few_typos": r.randint(1, 3), "four_failures": 4, "spread_out": 8}[variant]
        for _ in range(n_fail):
            b.add(ep, t, "POST", "/rest/user/login", 401, 26, ua)
            gap = {"few_typos": r.uniform(4, 15), "four_failures": r.uniform(1.5, 3.5),
                   "spread_out": r.uniform(30, 45)}[variant]
            t += timedelta(seconds=gap)
        b.add(ep, t, "POST", "/rest/user/login", 200, 831, ua)
    # SQL-looking and XSS-looking but harmless searches
    for prefix, scenario, queries in (("lk-sqli", "lookalike_sqli", BENIGN_SQL_LIKE),
                                      ("lk-xss", "lookalike_xss", BENIGN_XSS_LIKE)):
        for i, q in enumerate(queries):
            ep = "%s-%03d" % (prefix, i + 1)
            b.episode(ep, "look", scenario, "benign_search", False, "")
            b.add(ep, b.start(), "GET", "/rest/products/search?q=" + quote(q, safe=""),
                  200, r.randint(1500, 6000), b.browser())
    # ID browsing: a few products, fourteen in a row (one below the default threshold), slow walk
    variants = ["few_products"] * 10 + ["fourteen_in_a_row"] * 10 + ["slow_walk"] * 10
    for i, variant in enumerate(variants):
        ep = "lk-ie-%03d" % (i + 1)
        b.episode(ep, "look", "lookalike_id_enum", variant, False, "")
        ua = b.browser()
        t = b.start()
        first = r.randint(1, 20)
        n = {"few_products": r.randint(2, 5), "fourteen_in_a_row": 14, "slow_walk": 24}[variant]
        for k in range(n):
            pid = r.randint(1, 40) if variant == "few_products" else first + k
            b.add(ep, t, "GET", "/api/Products/%d" % pid, 200, r.randint(300, 900), ua)
            gap = {"few_products": r.uniform(5, 20), "fourteen_in_a_row": r.uniform(0.5, 1.5),
                   "slow_walk": r.uniform(25, 35)}[variant]
            t += timedelta(seconds=gap)
    # harmless non-browser clients
    for i in range(N_PER_SCENARIO):
        name, ua = BENIGN_TOOLS[i % len(BENIGN_TOOLS)]
        ep = "lk-sc-%03d" % (i + 1)
        b.episode(ep, "look", "lookalike_scanner", name, False, "")
        t = b.start()
        for _ in range(r.randint(3, 10)):
            b.add(ep, t, "GET", r.choice(BENIGN_PATHS), 200, r.randint(100, 5000), ua)
            t += timedelta(seconds=r.uniform(5, 60))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    force = "--force" in sys.argv
    log_path = Path(str(PREFIX) + ".log")
    labels_path = Path(str(PREFIX) + "-labels.csv")
    manifest_path = Path(str(PREFIX) + "-manifest.txt")
    if log_path.exists() and not force:
        sys.exit("%s already exists. The dataset is frozen; use --force only if you really mean "
                 "to replace it (and then redo every measurement)." % log_path)

    b = Builder(random.Random(SEED))
    build_background(b)
    build_brute_force(b)
    build_vuln_scanner(b)
    build_dir_scanner(b)
    build_injection(b, "sqli", "sqli", "AF-003", read_payloads("sqli"))
    build_injection(b, "xss", "xss", "AF-004", read_payloads("xss"))
    build_id_enum(b)
    build_lookalikes(b)

    b.events.sort(key=lambda e: (e[0], e[1]))  # chronological, ties keep creation order

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8", newline="\n") as log_file, \
            open(labels_path, "w", encoding="utf-8", newline="\n") as labels_file:
        writer = csv.writer(labels_file, lineterminator="\n")
        writer.writerow(["line_no", "source_ip", "label", "scenario", "variant", "episode_id",
                         "alert_expected", "expected_rule"])
        for n, (t, _seq, ip, method, target, status, size, ua, ep_id) in enumerate(b.events, 1):
            log_file.write('%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"\n'
                           % (ip, log_time(t), method, target, status, size, ua))
            ep = b.episodes[ep_id]
            writer.writerow([n, ip, "attack" if ep["attack"] else "normal", ep["scenario"],
                             ep["variant"], ep_id, 1 if ep["attack"] else 0, ep["expected_rule"]])

    by_scenario = {}
    for t, _s, _ip, _m, _tg, _st, _sz, _ua, ep_id in b.events:
        sc = b.episodes[ep_id]["scenario"]
        by_scenario.setdefault(sc, [0, 0])[1] += 1
    for ep in b.episodes.values():
        by_scenario.setdefault(ep["scenario"], [0, 0])[0] += 1

    attack_requests = sum(v[1] for k, v in by_scenario.items() if not (k == "background" or k.startswith("lookalike")))
    total = len(b.events)
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as m:
        m.write("dataset=AlertForge evaluation dataset v1\n")
        m.write("seed=%d\n" % SEED)
        m.write("total_requests=%d\n" % total)
        m.write("normal_requests=%d\n" % (total - attack_requests))
        m.write("attack_requests=%d\n" % attack_requests)
        m.write("episodes=%d\n" % len(b.episodes))
        for sc in sorted(by_scenario):
            m.write("scenario.%s=episodes:%d,requests:%d\n" % (sc, by_scenario[sc][0], by_scenario[sc][1]))
        m.write("log_sha256=%s\n" % sha256(log_path))
        m.write("labels_sha256=%s\n" % sha256(labels_path))

    print("wrote %s (%d requests), %s, %s" % (log_path, total, labels_path, manifest_path))
    print(manifest_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
