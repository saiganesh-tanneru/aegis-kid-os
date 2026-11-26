# Aegis-Kid OS (India Edition) — DPDP Compliance Checklist

| Field | Value |
|---|---|
| Document | `docs/dpdp-compliance-checklist.md` |
| Version | 1.0.0 — MVP |
| Date | 2026-11-25 |
| Status | **Compliance evidence map** — every row must have an implementation and an evidence link before MVP sign-off. A row marked "Not yet evidenced" blocks release. |
| Law | India's Digital Personal Data Protection Act, 2023 (DPDP Act) — full enforcement from **13 May 2027**, covering all minors **under 18** and **banning behavioural tracking of children** |
| Companion docs | `docs/01-architecture-threat-model.md`, `docs/data-flow-diagram.md`, `docs/age-tier-policies.md` |
| Roles | **Data Fiduciary:** Aegis (the company operating the backend and the DPC). **Data Principal (child):** the child using the tablet — a minor under 18, so consent must come from a **parent / lawful guardian** (verifiable parental consent). **Data Processor(s):** DigiLocker (parent verification), WhatsApp Business / SMS provider (breach alerts only) — each is a processor for the limited purpose stated in its row. |

> **Reading this checklist:** "Implementation" is what the code / process *does*. "Evidence" is what a reviewer can *check* — a file, a test, a log, or a diagram. If the evidence column says "code review" or "test", the reviewer must be able to run it. This checklist is not a legal opinion. It is an engineering trace from the DPDP Act's requirements to the MVP implementation. A qualified Indian data-privacy lawyer must review it before the product is offered to the public.

---

## 1. Scope & Applicability

| # | DPDP requirement (plain language) | Applies to Aegis? | Implementation | Evidence |
|---|---|---|---|---|
| 1.1 | The DPDP Act applies to processing of digital personal data in India, including data of minors under 18. Full enforcement from 13 May 2027. | Yes — all users are under 18; the product is offered in India. | The entire architecture is designed for under-18 users. No feature assumes an adult user on the child's device. The age-tier system (5–8, 9–12, 13–15, 16–17) is the enforcement mechanism. | `docs/age-tier-policies.md`; `docs/01-architecture-threat-model.md` §2.1 |
| 1.2 | A Data Fiduciary must process personal data only for a lawful purpose, with consent (or another lawful basis), and must limit processing to what is necessary for that purpose (data minimisation). | Yes | Lawful purpose is stated in the parent onboarding flow: *protecting a child on a tablet via a locked-down device, local content filtering, and tamper alerts*. Processing is limited to the three flows in `data-flow-diagram.md` §2.1 — heartbeat, unblock challenge, parent DigiLocker verification. No other processing exists. | `docs/data-flow-diagram.md` §2.1–2.2; parent onboarding copy (Deliverable 5) |
| 1.3 | **Behavioural tracking of children is banned.** No tracking, no behavioural monitoring, no targeted advertising at children. | Yes — this is the central constraint | **No behavioural tracking exists.** There is no browsing history, no app usage log, no search log, no screen recording, no location tracking, no advertising ID, and no behavioural profile. The heartbeat contains no behaviour. The classifier runs locally and its inputs are purged. See rows 3.1–3.6. | `docs/data-flow-diagram.md` §2.2 (NEVER list); `docs/01-architecture-threat-model.md` §5.3; code search: no `UsageStatsManager`, no `AccessibilityService` for tracking, no advertising ID API in Deliverables 2–4 (CI check) |

---

## 2. Verifiable Parental Consent (Minors Under 18)

| # | DPDP requirement | Implementation | Evidence |
|---|---|---|---|
| 2.1 | Processing a child's personal data requires **verifiable parental consent** — consent from a parent / lawful guardian, verified before processing begins. | Parent onboarding **requires DigiLocker verification** before a device can be bound. The DPC will not provision a device for a parent who has not completed DigiLocker verification. The backend stores only the *verification result* (verified / not verified, timestamp, DigiLocker reference ID), not the parent's full document. | `docs/data-flow-diagram.md` Sequence 2; `docs/01-architecture-threat-model.md` §4.9; Deliverable 5: `/v1/parents/verify` endpoint + test |
| 2.2 | Consent must be **free, specific, informed, unambiguous, and withdrawable**. The parent must know what is processed and why. | Parent onboarding presents, in plain language (English + Hindi in MVP, other languages as a follow-up): what leaves the device (the 3 flows), what never leaves, what the AI does locally, and what alerts the parent will receive. Consent is recorded as `{parent_id, consent_version, consented_at, digilocker_ref_id}`. Withdrawal = un-enrolment via Human Support after DigiLocker re-verification (see row 6.2). | Parent onboarding copy + consent record schema (Deliverable 5); `docs/data-flow-diagram.md` §2.1 |
| 2.3 | Consent must be **re-verified for sensitive actions** (not just at onboarding). | DigiLocker re-verification is required for: Tier 2 unblock escalations, age-tier upgrades, permanent unlocks, and device un-enrolment. A password / session token alone is never sufficient for these actions. | `docs/01-architecture-threat-model.md` §4.9, §8 T-12; `docs/data-flow-diagram.md` Sequence 3 (Tier 2) |
| 2.4 | The parent must be an **adult** (18+). | DigiLocker verification includes an adulthood flag derived from the parent's DigiLocker-verified date of birth. The backend checks `adulthood_flag == true` before binding a device. A parent who cannot be verified as an adult cannot bind a device. | Deliverable 5: DigiLocker assertion handling + test (adult flag false → binding rejected) |
| 2.5 | No consent is sought from the child. The child cannot consent to processing on their own behalf, and cannot override a parent's consent on the device. | There is no consent UI on the child's tablet. The "Ask a parent" flow is a *request*, not a consent. The child cannot grant, withdraw, or change consent from the device. | `docs/01-architecture-threat-model.md` §4.1–4.2 (no settings UI on device); test: no consent UI is reachable in the kiosk |

---

## 3. Data Minimisation & Purpose Limitation — Zero Cloud Logging

| # | DPDP requirement | Implementation | Evidence |
|---|---|---|---|
| 3.1 | **NEVER transmit browsing history to any cloud server.** | No code path sends browsing history. The Gatekeeper WebView keeps no history on disk; its in-memory session is cleared on close. The backend has no endpoint that accepts browsing history. | `docs/data-flow-diagram.md` §2.2; code search: no history API in Deliverable 3; backend API spec (Deliverable 5) — no history endpoint |
| 3.2 | **NEVER transmit app usage logs to any cloud server.** | No `UsageStatsManager` collection, no per-app usage counter sent to the backend. Screen-time counters are local only (see `age-tier-policies.md` §5). The heartbeat contains no app list. | Code search: no `UsageStatsManager` in Deliverables 2–4; `docs/data-flow-diagram.md` §2.1 (heartbeat fields) |
| 3.3 | **NEVER transmit screenshots to any cloud server.** | Screenshots are never taken for transmission. The OCR screen-guard runs on an in-memory bitmap that is discarded immediately after classification. No screenshot is saved, logged, or sent. | `docs/01-architecture-threat-model.md` §4.6; code review: OCR bitmap lifecycle in Deliverable 3 |
| 3.4 | **NEVER transmit search queries to any cloud server (Aegis backend).** | Search queries go to the allowlisted search provider (if the tier allows search), not to Aegis. Aegis never receives, logs, or stores a search query. The unblock challenge contains a URL/package ID, not a search query. | `docs/data-flow-diagram.md` §2.2; `docs/age-tier-policies.md` §2 (Search rows) |
| 3.5 | **NEVER transmit voice / text inputs to any cloud server.** | There is no voice input to Aegis, and no text input is sent to Aegis. The Gatekeeper does not send typed text to the backend. The unblock flow has no free-text field (prompt-injection defence). | `docs/01-architecture-threat-model.md` §4.9; `docs/data-flow-diagram.md` Sequence 3; API schema test: extra fields rejected with `400` |
| 3.6 | **All AI inspection, OCR, and content classification must execute 100% locally in volatile RAM and be purged immediately after the allow/block verdict.** | LiteRT classifier + OCR run on-device, in RAM, with no disk write and no network call. Inputs are explicitly cleared after the verdict. Models are quantized int8, < 300 MB total. No cloud content inspection for children exists in the MVP. | `docs/01-architecture-threat-model.md` §4.5–4.6; Deliverable 3: model loading + purge code + memory test (< 300 MB); test: classifier works in airplane mode |
| 3.7 | **What MAY leave the device is exhaustive and closed.** | Only three flows may leave: (1) heartbeat (6 fields), (2) unblock challenge (URL/package + age tier), (3) one-time attestation at provisioning. Parent DigiLocker data flows parent → DigiLocker → backend, never via the child's device. See the exhaustive table. | `docs/data-flow-diagram.md` §2.1; `docs/01-architecture-threat-model.md` §5.2 |
| 3.8 | **No location tracking.** | No GPS, no IP-derived location, no SSID, no cell ID is collected or sent. The heartbeat's `network_state` is `wifi` / `cellular` / `offline` only. Breach alerts contain no location. | Code search: no location permission in the DPC manifest; `docs/data-flow-diagram.md` §2.1 |
| 3.9 | **No advertising, no profiling, no behavioural advertising to children.** | No advertising SDK, no advertising ID, no behavioural profile, no targeted ads. The product has no ads. | Code search: no ads SDK in Deliverables 2–4; manifest review |

---

## 4. Security Safeguards (Reasonable Security Practices)

| # | DPDP requirement | Implementation | Evidence |
|---|---|---|---|
| 4.1 | Implement **reasonable security safeguards** to prevent a personal data breach (encryption, access control, etc.). | At-rest: file-based encryption (Android default) + EncryptedFile / EncryptedSharedPreferences for the heartbeat cache. In transit: TLS + Ed25519 signatures (heartbeat, tokens, policy). At the hardware level: non-exportable Keystore key in TEE / StrongBox + attestation. Access control: Device Owner restrictions + signed policy blobs + DigiLocker re-verification for sensitive actions. | `docs/01-architecture-threat-model.md` §4.7–4.8, §8; Deliverable 4: Keystore code + attestation test |
| 4.2 | **Breach detection and alerting.** | Dead-man heartbeat + attestation / boot-count anomaly + EFRP detection → `CRITICAL_TAMPER_BREACH` via WhatsApp Business + SMS to the parent (see architecture §7). The alert contains no child content. | `docs/01-architecture-threat-model.md` §7; `docs/data-flow-diagram.md` Sequence 4; Deliverable 5: dead-man evaluator + alerting tests |
| 4.3 | **Breach notification to the Data Protection Board / affected principals** (as required by the DPDP Act and Rules, when a breach occurs). | *Process, not code:* The ops runbook (Deliverable 5, ops section) must define: who is notified, within what time, and in what form, when a breach is confirmed. The backend must log breach *events* (not child content) in an audit log that the runbook can use. This checklist does not set the legal notification deadline — a lawyer must confirm it against the DPDP Rules in force at launch. | Ops runbook (Deliverable 5); audit-log schema (no child content in audit logs — see row 4.4) |
| 4.4 | **Audit logs must not contain child content.** | Backend audit logs record *events* (`heartbeat_verified`, `token_issued`, `breach_alert_sent`, `policy_applied`) with `device_id` and timestamps only. No URL, no page content, no search query, no screenshot is ever written to a log. Android logs (`Logcat`) on the device must not contain child content either — Deliverables 2–4 must not log URLs, page text, or OCR text. | Code review: no `Log.*` call with content in Deliverables 2–4; backend logging config (Deliverable 5); CI check: log-scan for URL / content patterns |
| 4.5 | **Key management.** | Backend Ed25519 private key in a cloud KMS / HSM in production (env-only placeholder in MVP — see architecture §11). Device signing key is non-exportable in TEE / StrongBox. Backend public key is pinned on the device at provisioning. Key rotation is via a signed rotation policy. | `docs/01-architecture-threat-model.md` §4.7, §11; Deliverable 4 + 5: key generation / rotation procedures |
| 4.6 | **No secrets in the repo.** | No real credentials, no API keys, no private keys in any file, test, or screenshot. Placeholders only (`${DIGILOCKER_CLIENT_ID}`, `${BACKEND_ED25519_PRIVATE_KEY}`, `${WHATSAPP_BUSINESS_API_TOKEN}`, `${SMS_PROVIDER_API_KEY}`). CI must fail on a secret-scan hit. | Repo secret-scan CI (to be added in Deliverable 5 setup); this checklist itself contains no secrets |

---

## 5. Children's Rights & Parental Rights

| # | DPDP requirement | Implementation | Evidence |
|---|---|---|---|
| 5.1 | **Right to access** — the parent (on behalf of the child) can ask what personal data is held. | The answer is auditable from this checklist: the backend holds (a) the parent's DigiLocker verification result, (b) the device record (`device_id`, `age_tier`, `policy_version`), (c) heartbeats (6 fields), (d) unblock request records (target + tier + token status). It holds *no* child browsing, usage, screenshot, search, or content data — so there is nothing to disclose in those categories. The parent dashboard (Deliverable 5) must present this list. | Parent dashboard data inventory (Deliverable 5); `docs/data-flow-diagram.md` §2.3 (stores table) |
| 5.2 | **Right to correction / erasure** — the parent can ask for data to be corrected or erased. | Erasure = un-enrolment + deletion of the backend device record, heartbeats, and token records for that `device_id`. The process is a Human Support request after DigiLocker re-verification. Local data on the tablet is erased by the factory reset that follows un-enrolment. The MVP must define the erasure SLA in the ops runbook. | Ops runbook (Deliverable 5); un-enrolment flow in `docs/01-architecture-threat-model.md` §4.1 |
| 5.3 | **Right to grievance redressal** — the parent can raise a grievance and must receive a response. | Human Support Queue (Deliverable 5) is the grievance channel. The queue schema must include a grievance category. The response SLA is an ops decision, not a code decision — it must be published to parents before launch. | Human Support Queue schema (Deliverable 5); published SLA (ops) |
| 5.4 | **No right to be forgotten for the *parent's* DigiLocker verification** in a way that breaks the audit trail — the verification *result* is retained for as long as the device is enrolled, then deleted on un-enrolment (see row 5.2). | Retention is stated in the parent onboarding copy. | Parent onboarding copy (Deliverable 5) |
| 5.5 | **The child has no account, no password, and no data subject portal on the device.** | By design. The child is not a registered user of the backend. All rights are exercised by the parent via the parent dashboard / Human Support. | `docs/01-architecture-threat-model.md` §4.1–4.2 |

---

## 6. Retention, Deletion & Un-Enrolment

| # | DPDP requirement | Implementation | Evidence |
|---|---|---|---|
| 6.1 | Retain personal data only as long as necessary for the lawful purpose; delete it when it is no longer needed. | Heartbeats: MVP retention 90 days, then delete (see `data-flow-diagram.md` §2.3). Tokens: until expiry + 30 days for audit, then delete. Parent verification result: until un-enrolment, then delete per row 5.2. Local heartbeat cache: max 144 entries (24 h), oldest-first eviction. Gatekeeper RAM: purged after each verdict. | Retention config (Deliverable 5); `docs/data-flow-diagram.md` §2.3 |
| 6.2 | **Un-enrolment** must be possible and must actually remove the Device Owner and delete the data. | Un-enrolment is a Human Support request after DigiLocker re-verification. The backend issues a signed un-enrolment token; the DPC verifies it and calls `clearDeviceOwnerApp()` / factory-resets via policy. The backend then deletes the device record, heartbeats, and tokens for that `device_id` per row 6.1. There is no local un-enrolment button for the child. | `docs/01-architecture-threat-model.md` §4.1; `docs/data-flow-diagram.md` Sequence 3 (Tier 2); Deliverable 5: un-enrolment endpoint + test |
| 6.3 | **Factory reset / EFRP** must not leave child data recoverable. | A recovery wipe triggers EFRP + re-enrolment + a breach alert (§7 of the architecture doc). The wiped device contains no child content in any case — the Gatekeeper keeps no history on disk and the heartbeat cache is encrypted and wiped with the reset. | `docs/01-architecture-threat-model.md` §8 T-04; test in the threat table |

---

## 7. Third Parties & Processors

| # | Processor / third party | Purpose (only) | Data shared | Safeguards |
|---|---|---|---|---|
| 7.1 | **DigiLocker** (Govt. of India) | Parent identity + adulthood verification | Parent identity assertion (parent data only). No child data. | OAuth 2.0; Aegis stores only the verification *result*, never the parent's full document or DigiLocker credentials. |
| 7.2 | **WhatsApp Business API** | Breach alerts to the parent | Alert text: breach category, device nickname, timestamp (IST). No child content, no URL, no location. | Provider contract (DPA) to be confirmed by a lawyer; alerts are sent from the backend, never from the device. |
| 7.3 | **SMS provider** | Breach alert fallback (if WhatsApp is not confirmed in 5 min) | Same alert text as 7.2. | Same as 7.2. |
| 7.4 | **Cloud AI Safety Adjudicator** (backend service) | Evaluate an unblock request (URL/package + age tier only) | Target URL/package ID + age tier only. No free text, no child PII, no content. | Closed input schema; extra fields rejected with `400`; ≥98% threshold; single-resource, 24-h tokens only. |
| 7.5 | **Cloud hosting provider** (backend) | Host the FastAPI backend + DB | Heartbeats (6 fields), token records, parent verification results. No child content. | At-rest encryption; access control; retention per §6. |
| 7.6 | **Google Play / Managed Google Play** | Deliver allowlisted apps | Package install requests (DPC-managed). No child content. | Managed Play in DO mode; installs only via the allowlist. |

**No other third party receives any data in the MVP.** Adding a processor requires a new row here, a DPA, and a DPDP review.

---

## 8. Age Assurance & Age-Tier Enforcement

| # | Requirement | Implementation | Evidence |
|---|---|---|---|
| 8.1 | Age tiers must be enforced, not just displayed. | The tier is bound at provisioning into a signed policy blob; the DPC enforces the tier's allowlist, rubric, search, YouTube, screen-time, and bedtime rules. The LiteRT rubric is per-tier. | `docs/age-tier-policies.md`; `docs/01-architecture-threat-model.md` §4.1, §4.5 |
| 8.2 | A child must not be able to change their age tier. | No tier-change UI on the device. Tier upgrade is a Tier 2 Human Support request after DigiLocker re-verification. Policy version monotonicity prevents rollback to a looser tier. | `docs/age-tier-policies.md` §6; `docs/01-architecture-threat-model.md` §4.7, §8 T-14 |
| 8.3 | The tier must be re-asserted on every boot. | DPC re-applies the signed policy on `BOOT_COMPLETED` and on every DPC start. | `docs/01-architecture-threat-model.md` §4.1; boot test |

---

## 9. Transparency — What Parents Are Told (Before Enrolment)

The parent onboarding flow must state, in plain language, all of the following. This is a *content* requirement for Deliverable 5, not a code requirement — but the MVP cannot ship without it.

- [ ] What leaves the device (the 3 flows, in plain language) and what never leaves.
- [ ] That all AI content checking happens on the device, in memory, and is deleted immediately after the decision.
- [ ] That Aegis does not track browsing, app usage, location, or messages, and does not serve ads to the child.
- [ ] That the AI filter is probabilistic and will sometimes block a legitimate page (use "Ask a parent") and sometimes miss harmful content (the firewall + allowlist are the backstop).
- [ ] That a recovery wipe removes the lock but triggers an immediate alert and forces re-enrolment.
- [ ] That breach alerts may take up to ~30–40 minutes (10-min heartbeat + grace window).
- [ ] That there is no parent PIN / local override on the device, and that unblocking a resource requires a backend round-trip.
- [ ] How to withdraw consent / un-enrol (Human Support + DigiLocker re-verification) and how long deletion takes.
- [ ] How to raise a grievance, and the published response SLA.
- [ ] The retention periods in §6.1.

---

## 10. Pre-Release Sign-Off

| # | Gate | Owner | Status |
|---|---|---|---|
| 10.1 | All rows in §§2–8 have an implementation and an evidence link | Engineering + Compliance | ☐ Not yet evidenced |
| 10.2 | Threat-model tests in `01-architecture-threat-model.md` §8 all pass on reference hardware (Lenovo Tab M / Galaxy Tab A, Android 12–16+) | Security reviewer | ☐ Not yet evidenced |
| 10.3 | LiteRT memory test passes (< 300 MB total) and classifier works in airplane mode | Engineering (Deliverable 3) | ☐ Not yet evidenced |
| 10.4 | Data-flow diagram (§2 of `data-flow-diagram.md`) matches the shipped code — no arrow in the code that is not in the diagram | Engineering + Compliance | ☐ Not yet evidenced |
| 10.5 | Secret scan passes; no real credentials in the repo | Engineering | ☐ Not yet evidenced |
| 10.6 | Parent onboarding copy (§9) is complete and reviewed | Product + Compliance | ☐ Not yet evidenced |
| 10.7 | **Qualified Indian data-privacy lawyer reviews this checklist and the parent onboarding copy before public launch** | Legal | ☐ Not yet evidenced |
| 10.8 | Ops runbook exists: breach notification, grievance SLA, erasure SLA, Human Support staffing | Ops | ☐ Not yet evidenced |

> **No row in this checklist may be marked "evidenced" on the basis of this document alone.** Evidence is a test run, a code review link, a screenshot of a passing test, or a signed legal review — not a paragraph in a Markdown file.

---

## Appendix — DPDP Act References (for the lawyer's review)

| Topic | DPDP Act reference (to be confirmed by counsel) |
|---|---|
| Verifiable parental consent for minors under 18; ban on behavioural tracking of children | DPDP Act, 2023, s. 9 (children's personal data) |
| Data Fiduciary duties: purpose limitation, data minimisation, reasonable security safeguards | DPDP Act, 2023, ss. 5–8 |
| Rights of the Data Principal (access, correction, erasure, grievance redressal) | DPDP Act, 2023, ss. 11–13 |
| Breach notification to the Data Protection Board of India | DPDP Act, 2023, s. 8(6) and the DPDP Rules |
| Full enforcement date | 13 May 2027 (per the MVP specification) |

*This appendix is a pointer for counsel, not a substitute for legal advice. Section numbers must be confirmed against the Act and the Rules in force at launch.*

---

*End of DPDP Compliance Checklist. Next: Deliverable 2 (DPC & Kiosk Launcher, Kotlin) must implement the controls traced in §§2–8 above.*
