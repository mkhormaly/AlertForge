# Attack payload sources

The SQL injection and XSS payloads of the evaluation dataset were NOT written for AlertForge.
They were drawn from public lists in SecLists (https://github.com/danielmiessler/SecLists, MIT licence),
master branch, retrieved 25 Nov 2026:

| Used for | Source files (path inside SecLists) |
|---|---|
| `sqli.txt` | `Fuzzing/Databases/SQLi/sqli.auth.bypass.txt`, `Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt` |
| `xss.txt`  | `Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt`, `XSS-RSNAKE.txt`, `XSS-BruteLogic.txt` |

Selection (`scripts/select_payloads.py`, seed 7): merge the lists, drop duplicates, keep entries that are
ASCII, 5-200 characters long and not a bare word, replace the `__TIME__` placeholder with `5`, then draw
30 payloads at random per category. The filters are objective and do not look at the detection rules.
The two selected files are committed so that the dataset can be regenerated without network access.
