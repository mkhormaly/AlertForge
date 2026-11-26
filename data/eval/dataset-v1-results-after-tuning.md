# AlertForge evaluation results

Dataset: `data/eval/dataset-v1` (hashes verified against the manifest)  
Run at: 2026-11-26T11:06:20.439648300Z

## Baseline (rules and thresholds as shipped)

| Rule | Title | Attack episodes | Detected | Detection rate | False-positive episodes | False-positive rate | Precision |
|---|---|---|---|---|---|---|---|
| AF-001 | Brute-force login attempts | 30 | 25 | 83.3% | 0 | 0.0% | 100.0% |
| AF-002 | Vulnerability scanner user-agent | 30 | 30 | 100.0% | 0 | 0.0% | 100.0% |
| AF-003 | SQL injection pattern in request | 30 | 30 | 100.0% | 0 | 0.0% | 100.0% |
| AF-004 | Cross-site scripting (XSS) pattern in request | 30 | 29 | 96.7% | 0 | 0.0% | 100.0% |
| AF-005 | Suspected IDOR - sequential object-ID enumeration | 30 | 25 | 83.3% | 0 | 0.0% | 100.0% |
| AF-006 | Directory / wordlist scanner user-agent | 30 | 30 | 100.0% | 0 | 0.0% | 100.0% |
| ALL | Overall | 180 | 169 | 93.9% | 0 | 0.0% | 100.0% |

Alerts raised: 807, of which 0 on normal traffic (0.00 per 1,000 normal requests); alerts not mapped to any episode: 0.

### Missed attack episodes (11)

- bf-029 [brute_force/slow] expected AF-001, rules that fired: none
- ie-027 [id_enum/slow] expected AF-005, rules that fired: none
- bf-027 [brute_force/slow] expected AF-001, rules that fired: none
- ie-029 [id_enum/slow] expected AF-005, rules that fired: none
- bf-026 [brute_force/slow] expected AF-001, rules that fired: none
- xss-022 [xss/single_request] expected AF-004, rules that fired: none
- ie-028 [id_enum/slow] expected AF-005, rules that fired: none
- bf-030 [brute_force/slow] expected AF-001, rules that fired: none
- ie-026 [id_enum/slow] expected AF-005, rules that fired: none
- ie-030 [id_enum/slow] expected AF-005, rules that fired: none
- bf-028 [brute_force/slow] expected AF-001, rules that fired: none

### False-positive episodes (0)


## AF-001: count (failed logins)

| count (failed logins) | Detection rate | Detected | False-positive episodes | False-positive rate | Precision |
|---|---|---|---|---|---|
| 3 | 100.0% | 30/30 | 14 | 7.4% | 68.2% |
| 4 | 83.3% | 25/30 | 10 | 5.3% | 71.4% |
| 5 (shipped) | 83.3% | 25/30 | 0 | 0.0% | 100.0% |
| 8 | 83.3% | 25/30 | 0 | 0.0% | 100.0% |
| 10 | 40.0% | 12/30 | 0 | 0.0% | 100.0% |

## AF-001: window (seconds)

| window (seconds) | Detection rate | Detected | False-positive episodes | False-positive rate | Precision |
|---|---|---|---|---|---|
| 30 | 80.0% | 24/30 | 0 | 0.0% | 100.0% |
| 60 (shipped) | 83.3% | 25/30 | 0 | 0.0% | 100.0% |
| 120 | 100.0% | 30/30 | 0 | 0.0% | 100.0% |
| 300 | 100.0% | 30/30 | 10 | 5.3% | 75.0% |

## AF-005: count (ID requests)

| count (ID requests) | Detection rate | Detected | False-positive episodes | False-positive rate | Precision |
|---|---|---|---|---|---|
| 5 | 100.0% | 30/30 | 10 | 5.3% | 75.0% |
| 10 | 86.7% | 26/30 | 10 | 5.3% | 72.2% |
| 15 (shipped) | 83.3% | 25/30 | 0 | 0.0% | 100.0% |
| 20 | 66.7% | 20/30 | 0 | 0.0% | 100.0% |
| 30 | 26.7% | 8/30 | 0 | 0.0% | 100.0% |

## AF-005: window (seconds)

| window (seconds) | Detection rate | Detected | False-positive episodes | False-positive rate | Precision |
|---|---|---|---|---|---|
| 15 | 66.7% | 20/30 | 0 | 0.0% | 100.0% |
| 30 (shipped) | 83.3% | 25/30 | 0 | 0.0% | 100.0% |
| 60 | 100.0% | 30/30 | 0 | 0.0% | 100.0% |
| 120 | 100.0% | 30/30 | 0 | 0.0% | 100.0% |

