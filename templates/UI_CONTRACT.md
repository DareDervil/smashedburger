# UI contract — JS hooks the overhaul markup MUST preserve

Generated 2026-06-11 for the v0.2 Tailwind overhaul. **Rule: zero JS logic edits.**
New markup may restyle/move elements freely but every hook below must keep existing,
with the same id/class, reachable in the DOM at script load time.

## Element IDs referenced by getElementById (60)

actions-container actions-empty back-to-dash-btn checklist-back checklist-body
checklist-nav-btn checklist-screen cl-done cl-pending cl-total conversation-list
dashboard detail-close-btn detail-rm-vendor-btn detail-vendor-avatar
detail-vendor-name infra-detail infra-detail-body infra-grid layout
links-container links-empty message-input messages my-infra my-infra-back
my-infra-nav-btn new-chat-btn open-chat-btn open-checklist-btn open-warroom-btn
pane-b-cve-filter save-checklist-btn send-btn stat-actions stat-chats stat-cves
stat-products warroom-back-btn warroom-body warroom-nav-btn warroom-screen
wr-critical wr-high wr-ioc-content wr-ioc-section wr-medium wr-open wr-panel
wr-panel-close wr-panel-cve-id wr-panel-date wr-panel-open-chat
wr-panel-progress-fill wr-panel-progress-text wr-panel-score
wr-panel-search-iocs wr-panel-sev-badge wr-panel-title wr-total

## Selectors used by querySelector/querySelectorAll

`#checklist-filter-bar .checklist-tab[data-status]` · `#checklist-filter-bar
.checklist-tab[data-type]` · `.action-checkbox` · `.action-checkbox:checked` ·
`.action-discard-btn` · `.action-tile` · `.cl-dismiss-btn` · `.cl-restore-btn` ·
`.cl-tick-btn` · `.conv-title` · `.del-btn` · `.infra-tab` · `.pb-cve-chip` ·
`.vendor-logo-card` · `.wr-row` · `.wr-tab`

## State classes toggled by JS (must keep these names; style them, don't rename)

`active` `all-done` `bubble` `hidden` `open` `selected` `visible`
(`hidden` = display:none on every screen — matches Tailwind's `.hidden` utility.)

## Screen-switching functions (global scope, classic script — wrappable)

`_hideAllScreens` `showDashboard` `showChat` `showChecklist` `showMyInfra` `showWarRoom`

## Overhaul conventions

- Tailwind Play CDN during migration (preflight DISABLED so legacy CSS keeps its
  assumptions); switch to standalone CLI build at Phase F packaging.
- Custom overrides live in `<style id="tw-overhaul">` placed AFTER the legacy
  stylesheet — later rules win ties while both coexist.
- Navbar is additive: new `nav-*` ids, bound in a new `<script>` block at the end
  of body; show* functions are wrapped (not edited) for active-state sync.
- Legacy per-screen CSS is deleted only in the step that restyles that screen.
- Unified palette (dark console): page `#1a1b2e`, surfaces `#1e1f2e/#1e2040`,
  raised `#2a2b3d`, line `#2e3050`, accent `#3b5bdb`, consultant purple `#6b46c1`,
  severity `#ff3b3b/#f97316/#f59e0b`, ok `#1a7f3c`, text `#e2e4ea/#9ea3b0/#6b7280`.
