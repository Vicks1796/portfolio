# Open investigations: briefs

Three projects listed on the site as open. Each is scoped so it can be finished in a few
weekends and moved into Exhibits with real evidence. Keep the repo for each one public from day
one; an empty repo with a README and a plan is already proof the case is open.

## Case A · NCA control mapper
Goal: a tool that maps NCA ECC and CSCC controls to ISO 27001:2022 Annex A and NIST CSF 2.0.
- Data: one JSON file per framework (id, title, domain, text), one JSON of mappings with a
  confidence note per link.
- Tool: Python CLI (`map.py --from ecc --to iso27001 --export csv`) plus a static HTML page that
  loads the JSON and shows a filterable matrix. No backend.
- Done when: every ECC domain has mappings, the README shows a worked example (pick one control,
  show its ISO and CSF twins and the gap it leaves), CSV export works.
- Evidence for the exhibit: screenshot of the matrix, link to the repo, the CSV.

## Case B · Telemetry link hardening
Goal: attack, then harden, the Cockpit White Box telemetry path.
- Phase 1, threat model: one diagram (STRIDE per element: sensor, NodeMCU, radio link, receiver,
  ATC display). List the assumptions the original build made.
- Phase 2, attack: capture frames, replay them, spoof altitude. Record what the receiver accepts.
- Phase 3, harden: HMAC-SHA256 on each frame with a per-device key, sequence numbers to kill
  replay, MQTT over TLS to the receiver. Measure added latency and power draw.
- Done when: the same replay and spoof scripts fail against the hardened build and the write-up
  shows both runs side by side.
- Evidence for the exhibit: the diagram, the two capture logs, the latency table.

## Case C · Web application assessment report
Goal: a client-ready penetration test report on OWASP Juice Shop (or DVWA).
- Scope and rules of engagement page, methodology (OWASP WSTG), tools (Burp Community, browser
  devtools, a few hand-written scripts).
- At least ten verified findings, each with: title, OWASP Top 10 category, CVSS 3.1 vector and
  score, reproduction steps, evidence screenshot, remediation, references.
- Executive summary first, one page, written for a non-technical reader.
- Done when: the PDF is published and the findings table is also on the repo README.
- Evidence for the exhibit: the PDF, the findings table.
