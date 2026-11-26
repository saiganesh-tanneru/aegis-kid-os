# Aegis-Kid OS (India Edition) — Age-Tier Policy Matrix

| Field | Value |
|---|---|
| Document | `docs/age-tier-policies.md` |
| Version | 1.0.0 — MVP |
| Date | 2026-11-25 |
| Status | **Normative policy** — the signed policy blob (§4.1 of `01-architecture-threat-model.md`) must encode exactly these tiers; the DPC must enforce the tier bound at provisioning and must reject a policy whose tier does not match the bound tier |
| Companion docs | `docs/01-architecture-threat-model.md` (§4, §8), `docs/data-flow-diagram.md`, `docs/dpdp-compliance-checklist.md` |
| Age tiers | **5–8, 9–12, 13–15, 16–17** — all under 18, all covered by the DPDP Act. There is no "18+" tier on a child's device. |

> **Binding rule:** The age tier is bound cryptographically at provisioning (QR payload → signed policy blob → DPC). It cannot be changed on the device. A tier upgrade is a Tier 2 Human Support request after DigiLocker parent re-verification (see `01-architecture-threat-model.md` §4.9). A child cannot age themselves up by changing a setting, a date of birth, or the device clock.

---

## 1. How to Read This Document

- **Allowed** = the category / capability is available, subject to the allowlist + LiteRT gatekeeper. "Allowed" never means "unfiltered" — every web request still goes through the VpnService DNS/SNI firewall and, if not allowlisted, through the LiteRT classifier.
- **Blocked** = the DPC / firewall / launcher enforces a block. There is no local override.
- **Via unblock flow only** = the child can request it via the Ed25519 unblock challenge (§4.9 of the architecture doc). The Cloud AI may auto-approve it (≥98%, 24 h, single resource) or escalate it to Human Support. It is not available by default.
- **Default** = the out-of-the-box value at provisioning. A parent may *tighten* a default via Human Support; a parent may not *loosen* a blocked category on the device.
- **Screen-time defaults** are defaults, not hard limits enforced by the OS in the MVP beyond the daily cap. The daily cap is enforced by the DPC (LockTask exit / app blocking at the cap). Bedtime is enforced by the DPC locking the device to a "bedtime" screen.

---

## 2. Policy Matrix — All Four Tiers

### 2.1 At a glance

| Category | 5–8 | 9–12 | 13–15 | 16–17 |
|---|---|---|---|---|
| **Web browsing (Gatekeeper WebView)** | Allowlisted sites only | Allowlisted + child-safe search | Allowlisted + search + LiteRT-gated general web | Allowlisted + search + LiteRT-gated general web (wider rubric) |
| **Search** | No general search; in-app search in allowlisted apps only | Child-safe search provider only (e.g. Kiddle / SafeSearch-locked provider) | Child-safe search, SafeSearch locked on | General search, SafeSearch locked on; queries never logged |
| **YouTube** | YouTube Kids only | YouTube Kids only | YouTube Kids + YouTube (Restricted Mode locked) via unblock flow only | YouTube (Restricted Mode locked) |
| **YouTube Kids** | Allowed | Allowed | Allowed | Allowed |
| **EdTech (PW, DIKSHA/NCERT, Khan, Unacademy, BYJU'S/Aakash)** | Allowed (signature-verified + CDN allowlist) | Allowed | Allowed | Allowed |
| **Social media** | Blocked | Blocked | Blocked | Blocked — via Human Support only, never auto-approved |
| **Messaging / chat** | Blocked | Blocked | Blocked | Blocked — via Human Support only, never auto-approved |
| **Video / streaming (non-EdTech)** | Blocked | Blocked | Via unblock flow only | Via unblock flow only |
| **Games** | Allowlisted educational games only | Allowlisted educational + age-rated games | Allowlisted games (PEGI / IARC age-rated) | Allowlisted games |
| **News** | Blocked | Child-safe news only (allowlisted) | Child-safe news + LiteRT-gated news | LiteRT-gated news |
| **UPI / payments (GPay, PhonePe, Paytm, BHIM)** | Blocked | Blocked | Blocked | Blocked |
| **Play Store / installs** | Blocked (DPC-managed only) | Blocked (DPC-managed only) | Blocked (DPC-managed only) | Blocked (DPC-managed only) |
| **In-app purchases / Play billing** | Blocked | Blocked | Blocked | Blocked |
| **SMS / OTP** | Blocked | Blocked | Blocked | Blocked |
| **Camera / mic** | Blocked in browser; allowlisted apps only with parent consent at install | Blocked in browser; allowlisted apps only | Allowlisted apps only | Allowlisted apps only |
| **Downloads** | Blocked | Blocked | Allowlisted file types only (PDF, images for school) | Allowlisted file types only |
| **Screen-time default (daily cap)** | 1 hour | 1.5 hours | 2 hours | 3 hours |
| **Bedtime (default, IST)** | 20:00–07:00 locked | 21:00–07:00 locked | 22:00–06:30 locked | 23:00–06:30 locked |
| **OCR screen-guard strictness** | Strictest — sample every 30 s on unverified screens | Strict — sample every 60 s | Standard — sample every 120 s | Standard — sample every 120 s |
| **LiteRT rubric strictness** | Strictest | Strict | Standard | Standard (widest) |
| **Unblock auto-approve** | Only unindexed NCERT / DIKSHA / school material | NCERT / DIKSHA / coding tools / school material | + general educational articles | + general educational articles |

### 2.2 Detailed per-tier policy

#### Tier A — Ages 5–8 ("Early Learner")

**Philosophy:** Walled garden. The child should not be able to reach the open web at all, even by accident.

| Item | Policy |
|---|---|
| Allowed categories | Signature-verified EdTech (PW Kids / DIKSHA / Khan Kids / YouTube Kids), allowlisted educational games, allowlisted story / rhyme apps. No general web. |
| Blocked categories | Social, messaging, video (non-EdTech), news, shopping, UPI/payments, search engines, email, app stores. All blocked by the firewall, not just hidden in the launcher. |
| Search | No general search. In-app search inside allowlisted apps only (e.g. search within Khan Kids). No search query is logged or sent to Aegis. |
| YouTube | YouTube Kids only. YouTube (main) is blocked, including via a link inside an allowlisted app. |
| Social / messaging | Blocked. No exceptions via auto-approve. A request for social/messaging goes to Human Support and is expected to be denied for this tier. |
| UPI / financial | Blocked by package (GPay, PhonePe, Paytm, BHIM) + Play billing blocked. |
| Installs | No installs by the child. Installs only via DPC / Managed Google Play allowlist, approved by the parent via Human Support. |
| Screen-time default | 1 hour/day. Bedtime 20:00–07:00 IST — device locks to a bedtime screen; no apps launch. |
| OCR strictness | Strictest. Sample unverified screens every 30 s. Any OCR hit above the tier threshold blocks the screen and returns to the launcher. |
| LiteRT rubric | Strictest. Blocks: violence, sexual content, scary / horror, gambling, advertising / commercial persuasion, chat / social features, user-generated comments, external links. Hinglish / Romanized Hindi is classified with the same strictness as English. |
| JavaScript in Gatekeeper | Disabled by default for this tier (allowlisted EdTech apps use their native apps, not the WebView). |
| Unblock auto-approve | Only unindexed NCERT / DIKSHA / school material, at ≥98% confidence, 24 h, single resource. Everything else → Human Support. |
| Example allowlisted | YouTube Kids, Khan Academy Kids, DIKSHA, NCERT e-Pathshala, PW (age-appropriate section), allowlisted puzzle / phonics games. |

#### Tier B — Ages 9–12 ("Explorer")

**Philosophy:** Guided exploration. Child-safe search is introduced; the open web is still not available.

| Item | Policy |
|---|---|
| Allowed categories | All of Tier A, plus child-safe search, child-safe news (allowlisted), educational games (age-rated), coding tools for kids (e.g. Scratch — via allowlist). |
| Blocked categories | Social, messaging, video (non-EdTech), shopping, UPI/payments, email, general web (non-allowlisted domains). |
| Search | Child-safe search provider only (e.g. Kiddle or a SafeSearch-locked provider named in the signed policy). SafeSearch is locked on and cannot be toggled in the Gatekeeper. Search queries are never logged or sent to Aegis. |
| YouTube | YouTube Kids only. YouTube (main) is blocked. |
| Social / messaging | Blocked. No auto-approve. Human Support only. |
| UPI / financial | Blocked (same as Tier A). |
| Installs | DPC-managed only. |
| Screen-time default | 1.5 hours/day. Bedtime 21:00–07:00 IST. |
| OCR strictness | Strict. Sample unverified screens every 60 s. |
| LiteRT rubric | Strict. Blocks: sexual content, graphic violence, gambling, hate, self-harm, social / chat, user-generated comments on non-allowlisted sites, advertising that targets children. Allows: educational content, child-safe news, coding, science, maths, stories. |
| JavaScript in Gatekeeper | Enabled for allowlisted / child-safe search domains only. |
| Unblock auto-approve | Unindexed NCERT / DIKSHA / school material + coding tools (e.g. Scratch, Code.org) at ≥98%, 24 h, single resource. |
| Example allowlisted | Tier A + Kiddle / child-safe search, Scratch, Code.org, child-safe news (e.g. The Hindu Young World / equivalent allowlisted), Khan Academy, Unacademy (age-appropriate), BYJU'S / Aakash (age-appropriate). |

#### Tier C — Ages 13–15 ("Teen — Supervised")

**Philosophy:** Supervised general web. The LiteRT gatekeeper becomes the main filter, not just the allowlist. Social and messaging remain blocked.

| Item | Policy |
|---|---|
| Allowed categories | All of Tier B, plus LiteRT-gated general web (non-allowlisted domains that pass classification), LiteRT-gated news, allowlisted games (PEGI / IARC age-rated for 13+). |
| Blocked categories | Social, messaging, UPI/payments, shopping (purchase), gambling, adult content, hate, self-harm. Video (non-EdTech) via unblock flow only. |
| Search | Child-safe search, SafeSearch locked on. General search engines (e.g. Google / Bing) only via the Gatekeeper with SafeSearch locked on — the search provider itself is not the filter; LiteRT + the firewall are. |
| YouTube | YouTube Kids + YouTube (Restricted Mode locked) via unblock flow only. A YouTube video URL requested via unblock is evaluated as a single resource; a YouTube *channel* or *search* is not auto-approved. |
| Social / messaging | Blocked. No auto-approve. Human Support only, and only after DigiLocker re-verification. The Human Support reviewer must apply the "13–15 social" guidance in the ops runbook (Deliverable 5). |
| UPI / financial | Blocked (same as Tier A). No exception at this tier. |
| Installs | DPC-managed only. |
| Screen-time default | 2 hours/day. Bedtime 22:00–06:30 IST. |
| OCR strictness | Standard. Sample unverified screens every 120 s. |
| LiteRT rubric | Standard. Blocks: sexual / adult, graphic violence, gambling, hate, self-harm, social / chat features, UPI / payment flows. Allows: educational, news, science, coding, general knowledge, age-appropriate entertainment (LiteRT-gated). Hinglish, Telugu, Tamil, and regional languages are classified with the same rubric as English — a harmful Hinglish page is blocked even if the English equivalent would be. |
| JavaScript in Gatekeeper | Enabled for LiteRT-allowed domains. |
| Downloads | Allowlisted file types only (PDF, images for school). Executables, APKs, and archives are blocked. |
| Unblock auto-approve | General educational articles + coding tools at ≥98%, 24 h, single resource. Social / messaging / permanent unlocks → Human Support. |

#### Tier D — Ages 16–17 ("Older Teen — Widest, Still Locked")

**Philosophy:** Widest rubric, but the lockdown does not lift. UPI, social auto-approve, and local override remain blocked. This tier is still a child's device under DPDP.

| Item | Policy |
|---|---|
| Allowed categories | All of Tier C, plus YouTube (Restricted Mode locked) by default, LiteRT-gated general web with the widest rubric, LiteRT-gated news. |
| Blocked categories | UPI/payments, gambling, adult content, hate, self-harm, shopping (purchase). Social / messaging: blocked by default, Human Support only (never auto-approved). |
| Search | General search, SafeSearch locked on. Queries never logged. |
| YouTube | YouTube (Restricted Mode locked) allowed. YouTube Kids also allowed. |
| Social / messaging | Blocked by default. A request goes to Human Support after DigiLocker re-verification. The AI adjudicator must *never* auto-approve social / messaging for any tier, including 16–17. |
| UPI / financial | Blocked. No exception at any tier, including 16–17. A 17-year-old does not get UPI on a child's device. |
| Installs | DPC-managed only. |
| Screen-time default | 3 hours/day. Bedtime 23:00–06:30 IST. |
| OCR strictness | Standard. Sample unverified screens every 120 s. |
| LiteRT rubric | Standard (widest). Blocks: sexual / adult, graphic violence, gambling, hate, self-harm, UPI / payment flows, social / chat features on non-allowlisted sites. Allows: educational, news, career / exam prep, coding, general knowledge, age-appropriate entertainment. |
| JavaScript in Gatekeeper | Enabled for LiteRT-allowed domains. |
| Downloads | Allowlisted file types only (PDF, images for school). |
| Unblock auto-approve | General educational articles + coding tools at ≥98%, 24 h, single resource. Same as Tier C, with a wider rubric for what counts as "educational." |

---

## 3. Categories — Definitions (normative)

| Category | Definition for policy purposes |
|---|---|
| **EdTech (allowlisted)** | An app that is (a) on the signed allowlist by package + signature, (b) whose primary purpose is education, and (c) whose CDN/domain list is in the signed policy. Examples: PW / Physics Wallah, NCERT / DIKSHA, Khan Academy, Unacademy, BYJU'S / Aakash, YouTube Kids. A general app that *contains* educational content is not EdTech for this purpose. |
| **Child-safe search** | A search provider named in the signed policy, with SafeSearch locked on, that does not serve adult ads and does not require an account. The provider is not trusted as the filter — LiteRT + the firewall still apply to results. |
| **Social media** | Any platform whose primary purpose is user-generated posts, following, liking, or commenting (e.g. Instagram, Snapchat, X, Facebook). Blocked at every tier by default. |
| **Messaging / chat** | Any app or web feature whose primary purpose is 1:1 or group messaging, including in-app chat in a game or EdTech app that is not part of the allowlisted educational function. Blocked at every tier by default. |
| **UPI / financial** | Any UPI app (GPay, PhonePe, Paytm, BHIM), any banking app, any wallet, Play Store billing, and any in-app purchase flow. Blocked at every tier, no exceptions. |
| **Video / streaming (non-EdTech)** | Video platforms and streaming services that are not signature-verified EdTech (e.g. general YouTube, Netflix, Hotstar). YouTube is handled separately above. |
| **Games** | Games are allowlisted by package + IARC / PEGI age rating. A game with an in-app chat feature is treated as messaging and is blocked unless the chat is disabled by policy and verified. |
| **News** | News sites are allowlisted (child-safe) for Tiers A–B, and LiteRT-gated for Tiers C–D. |

---

## 4. Allowlisted EdTech Apps & CDN Bypass (normative)

The following apps, **when signature-verified and on the signed allowlist**, bypass *deep packet inspection* (DPI) for their video streams — but **not** the DNS/SNI firewall. The firewall still checks that the destination is on that app's signed CDN/domain list.

| App | Package (example — verify at build time) | CDN / domain list | Notes |
|---|---|---|---|
| Physics Wallah (PW) | `com.physicswallah.live` — verify | Per signed policy (PW CDN domains) | Video playback bypasses DPI; web navigation via the Gatekeeper is still classified |
| NCERT / DIKSHA | `in.gov.diksha.app` — verify | Per signed policy (DIKSHA / NCERT domains) | Includes e-Pathshala content |
| Khan Academy | `org.khanacademy.android` — verify | Per signed policy (Khan CDN) | Khan Kids for Tier A |
| Unacademy | `com.unacademy` — verify | Per signed policy | Age-appropriate sections only; the allowlist is per-section where the app supports it, otherwise the whole app is gated by the tier rubric |
| BYJU'S / Aakash | `com.byjus.thelearningapp` — verify | Per signed policy | Age-appropriate sections only |
| YouTube Kids | `com.google.android.apps.youtube.kids` — verify | Per signed policy (YouTube Kids domains) | YouTube (main) is a separate package and is handled per-tier above |

> **Package names are examples and must be verified at build time against the Play Store listing.** The authoritative list is the signed policy blob, not this document. If a package name or signature changes, the allowlist must be updated by a signed policy update — not by editing this file.

**CDN abuse rule:** If a CDN domain on this list is found serving harmful content (see T-10 in the architecture doc), the domain is removed from the signed policy by an emergency policy update. The DPC must apply a policy update within one sync (target: < 1 hour from issuance).

---

## 5. Screen-Time & Bedtime Enforcement

| Rule | Enforcement |
|---|---|
| Daily cap | DPC tracks *foreground time in allowlisted apps + Gatekeeper* locally (anonymous counter, no per-app log sent to the backend). At the cap, the DPC locks the device to a child-safe "time's up" screen. The cap resets at midnight IST. |
| Bedtime | DPC locks the device to a bedtime screen during the bedtime window. No apps launch. An alarm / emergency call (if the device supports it) is not blocked — the bedtime screen must still allow an emergency call where the platform provides it. |
| Parent tightening | A parent may request a *lower* cap or an *earlier* bedtime via Human Support. A parent may not request a higher cap or a later bedtime on the device — that is a Tier 2 request and is reviewed as a policy change. |
| Screen-time data | Screen-time counters are local only. They are never sent to the backend, never included in a heartbeat, and never shown to anyone except on the device's own parent dashboard view (which requires DigiLocker re-verification to access remotely — see Deliverable 5). |

---

## 6. Policy Change & Versioning

| Rule | Detail |
|---|---|
| Policy version | Every signed policy blob carries a monotonically increasing `policy_version`. The DPC rejects a policy with a lower version (rollback protection). |
| Tier change | A tier change is a new signed policy blob + a Human Support approval after DigiLocker re-verification. The DPC applies it on the next sync and re-asserts the launcher / allowlist for the new tier. |
| Allowlist change | Adding or removing an app or a CDN domain is a signed policy update. Emergency removal (T-10) is a priority update. |
| Rubric change | Changing a LiteRT rubric threshold is a signed policy update. The rubric is not hard-coded in the app. |
| Audit | Every policy version applied is recorded locally as `{policy_version, applied_at}` — no content, no child data. The backend records `{device_id, policy_version, applied_at}` as part of the device record. |

---

## 7. Test Matrix (per tier — required for MVP validation)

For each tier, the following must be tested on reference hardware before the tier is declared ready:

| # | Test | Tiers |
|---|---|---|
| 1 | Launch an allowlisted EdTech app; verify video plays and the firewall allows only its CDN domains | All |
| 2 | Attempt to open an unapproved domain in the Gatekeeper; verify LiteRT blocks it (or allows it, per the tier rubric) | All |
| 3 | Attempt to open Google / a search engine in the Gatekeeper; verify per-tier search policy | All |
| 4 | Attempt to open YouTube (main) / YouTube Kids; verify per-tier YouTube policy | All |
| 5 | Attempt to open Instagram / WhatsApp / a messaging app; verify blocked at every tier | All |
| 6 | Attempt to open GPay / PhonePe / Paytm / BHIM; verify blocked at every tier | All |
| 7 | Attempt to install an APK / open Play Store; verify blocked | All |
| 8 | Attempt a Hinglish harmful page (text + image-as-text); verify LiteRT blocks it per the tier rubric | All |
| 9 | Request an unblock for an NCERT article; verify auto-approve (≥98%) + 24-h token + expiry | All |
| 10 | Request an unblock for a social platform; verify it goes to Human Support, not auto-approve | All |
| 11 | Reach the daily screen-time cap; verify the device locks | All |
| 12 | Enter the bedtime window; verify the device locks to the bedtime screen | All |

---

*End of Age-Tier Policies. Next: `docs/dpdp-compliance-checklist.md` for the DPDP evidence mapping.*
