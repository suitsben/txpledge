# txpledge — approve a transaction *before* it exists

**txpledge** lets you define a human-readable **pledge** for a transaction
(“I agree to call `approve(spender, MAX)` on token X with 0 ETH value”), then
later verify a raw Ethereum transaction hex **matches that pledge exactly**.
It’s fully offline and perfect for CI, multisig reviews, or audits.

## What it checks

- `to` address (checksum-normalized)
- `value_wei` (exact match)
- **Selector** (4-byte) — from `--selector` or inferred from `--abi`
- Optional **ABI-encoded args** (if you supplied `--abi` + `--arg ...`)
- Optional `chain_id` (checked for typed 0x02 transactions)
- The pledge’s **fingerprint** (Keccak-256 of a canonical JSON)

You can also **sign the pledge** (EIP-191 `personal_sign`) so others can verify
*who* issued the pledge.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
