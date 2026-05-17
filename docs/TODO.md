# TODO

Central list of deferred work for the v0.3 search router. Each entry
links the owning spec section, names the dependency that's blocking,
and points at where the seam lives in code so a future PR is a focused
change.

This doc is the canonical place — don't sprinkle TODOs across module
docstrings. If something here unblocks, move it to a regular issue
(`gh issue create`) and link from this list.

---

## Blocked on a vetted external dependency

These cannot ship without a library: spec §27.10 forbids hand-rolling
the blind-signature primitive, and §2 lists DC-net as a non-goal for
this version's formal crypto proof. The data layer + tests for each
are already in the repo so the future PR is small.

### TODO-1 · Phase 4 · LAN_FRIEND_DCNET adapter
- **Spec:** §17 (interface), §29.7 (responsibilities), §27.30 (timing)
- **Blocked on:** a Python DC-net implementation (none currently in
  the ecosystem).
- **What lands when unblocked:**
  - new module `src/swf/search/lan_friend_dcnet.py` matching the
    `RouteHandler` interface (already exported from `route.py`)
  - registers as `_HANDLERS[DeliveryPath.LAN_FRIEND_DCNET]` in
    `router.py:88`
- **Invariants already enforced:** §29.2 says any DCNET response must
  be labeled `anonymous_within_lan_circle_query_visible`; if you
  forget, `validate_invariants` raises. See
  `src/swf/search/response.py:255-263` and the
  `test_lan_friend_dcnet_must_label_anonymous_query_visible` case.
- **Workaround until then:** the router emits
  `route_not_implemented` for this path so partial responses are
  honest about the gap.

### TODO-2 · Phase 6B · Query-ticket issuance / verification
- **Spec:** §27.3 (crypto family), §27.9 (issuance flow), §27.10 (do
  NOT invent a new scheme), §27.11 (redemption)
- **Blocked on:** RFC 9474 (publicly-verifiable blind RSA) or RFC 9578
  (VOPRF tokens) Python implementation.
- **What lands when unblocked:** swap the body of two functions in
  `src/swf/search/tickets.py`:
  1. `verify_signature(envelope, issuer_key) -> bool` — currently
     raises `NotImplementedError` with the spec pointer.
  2. `nullifier_for(envelope) -> str` — currently sha256-keyed; may
     change if the library prescribes a different canonical token
     encoding.
- **Tests that already encode the expected shape:**
  `tests/search/test_tickets.py` — every rejection path is covered
  except the actual `verify_signature` happy path. The
  `test_verify_signature_raises_not_implemented` case must be deleted
  when the real impl lands; the rest stay.
- **Cross-peer nullifier sync** (§27 abuse model): out of scope for
  6B; lands as 6C.

### TODO-3 · Phase 6D-J · Anonymous receipts + service proofs
- **Spec:** §27.15-§27.27
- **Status:** interface stub shipped in PR #41 (`src/swf/search/receipts.py`).
  Same default-off pattern as Phase 4 / 6B/C: `SWF_ENABLE_RECEIPTS=1`,
  `ReceiptProvider` Protocol, null default that never accepts. Pinned
  by 35 tests in `tests/search/test_receipts.py` including the
  §27.21 privacy-by-construction check on `PublicBoardRecord`.
- **Blocked on:** the same Privacy Pass library TODO-2 needs. Receipts
  share the blind-token primitive (`tickets.verify_signature()` is the
  one shared seam).
- **What still needs to land when unblocked:**
  - real `ReceiptProvider` implementation against the Privacy Pass
    library; replace `_NullReceiptProvider`
  - wire the §27.20.2 / §27.20.3 / §27.20.4 delivery transports
    (direct-encrypted, LAN board, DC-net round). The `DeliveryMode`
    enum is in place; the senders are not.
  - `provider_service_proof.py` for §27.16 PROVIDER_SERVICE_PROOF_V1
    issuance/verification (the receipt verifier already requires
    `service_proof_hash`; the *minting* path is what's missing)
  - wires the existing `reputation.bump(.., "receipt_validated")`
    hook (already implemented; just unused). See
    `src/swf/search/reputation.py:35`.

---

## Implementation TODOs (no external blocker)

These are owned in-repo. Each could be a focused PR.

---

## Documentation / process


---

## How to keep this list honest

- When a TODO ships, **delete** the row (don't strikethrough). The
  commit log + PR history already documents what was done; this file
  documents only what's open.
- When a TODO turns out to be wrong (spec changed, dep resolved,
  scope shifted), say so in the PR that drops it.
- Order doesn't imply priority — number suffixes are stable
  identifiers so cross-references stay valid (e.g.
  "see TODO-2" in a future PR description).
