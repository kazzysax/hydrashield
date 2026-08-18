# Three-minute demo script

## 0:00–0:20 — Problem

“At 09:00, an npm package used deep inside our dependency tree is compromised. Keyword search finds direct imports, but security needs the complete transitive blast radius before the malicious release spreads.”

## 0:20–0:45 — Ingestion

Show the sample `package-lock.json`, then the dashboard graph counts. Explain that applications and exact package versions are stored in HydraDB.

## 0:45–1:20 — Replay

Click **Replay incident**. Pause at 09:00 and then 09:02. Show the graph lighting up from the compromised package back to internal applications.

## 1:20–1:55 — Evidence

Open Checkout API. Read the path:

`Checkout API → checkout-sdk@4.1.0 → request-helper@2.7.0 → package-x@3.2.1`

Say: “HydraShield never labels an application exposed without a real HydraDB path.”

## 1:55–2:25 — Remediation

Show how shared transitive packages allow one upgrade to cut multiple routes. Explain the graph-cut recommendation and production-first ordering.

## 2:25–2:45 — Proof

Show `make benchmark` returning precision `1.0` and recall `1.0`, then `/api/health` returning `HydraDBGraph`.

## 2:45–3:00 — Close

“Vector search finds similar text. HydraShield finds every attack path, proves every claim and tells the team where to cut the graph.”

