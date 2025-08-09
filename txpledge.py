#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
txpledge — make a human-readable transaction pledge and verify a raw tx against it (offline).

Commands
  create       Create a pledge JSON (canonicalized + fingerprint, optional signer signature)
  verify-tx    Verify a raw tx hex matches the pledge (to/value/selector/args/chain)
  fingerprint  Print the canonical fingerprint of a pledge JSON/string
  svg-badge    Emit a small SVG badge with verification status

Examples
  # Minimal pledge: to + value + selector (approve)
  $ python txpledge.py create --to 0xSpender... --value-wei 0 --selector 0x095ea7b3 > approve_pledge.json

  # Pledge with ABI + args (encode to exact calldata prefix)
  $ python txpledge.py create \
      --to 0xToken... \
      --value-wei 0 \
      --abi "approve(address,uint256)" \
      --arg 0xSpender... \
      --arg 115792089237316195423570985008687907853269984665640564039457584007913129639935 \
      > approve_inf.json

  # Verify a raw tx hex against the pledge
  $ python txpledge.py verify-tx approve_inf.json 0x02f8...

  # (Optional) sign the pledge with your key (EIP-191 personal_sign)
  $ export TXPLEDGE_PRIVKEY=0xabc...; python txpledge.py create ... > signed.json

Notes
- Fully offline. No RPC or internet.
- If ABI/args are provided, txpledge checks the calldata begins with selector+encoded args.
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import click
import rlp
from eth_utils import keccak, to_checksum_address

# Optional ABI/Signature deps
try:
    from eth_abi import encode as abi_encode
except Exception:  # pragma: no cover
    abi_encode = None

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
    HAVE_SIGN = True
except Exception:  # pragma: no cover
    HAVE_SIGN = False

UINT256_MAX = (1 << 256) - 1

# ----------------------- helpers -----------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def kjson(obj: Any) -> str:
    """Canonical JSON (sorted keys, no spaces) used for fingerprinting."""
    def _deep_sort(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: _deep_sort(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_deep_sort(x) for x in o]
        return o
    return json.dumps(_deep_sort(obj), separators=(",", ":"), ensure_ascii=False)

def keccak_hex(b: bytes) -> str:
    return "0x" + keccak(b).hex()

def as_addr_maybe(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = s.strip()
    if not s.startswith("0x") or len(s) != 42:
        return s
    try:
        return to_checksum_address(s)
    except Exception:
        return s

def to_int(x: Any) -> Optional[int]:
    try:
        if isinstance(x, str) and x.startswith("0x"):
            return int(x, 16)
        return int(x)
    except Exception:
        return None

def sel_from_abi(sig: str) -> str:
    from eth_utils import keccak as k
    return "0x" + k(text=sig)[:4].hex()

def enc_args(types: List[str], args: List[str]) -> bytes:
    if abi_encode is None:
        raise click.ClickException("eth-abi is not installed; cannot encode args. See requirements.txt.")
    # Normalize numbers
    norm = []
    for t, a in zip(types, args):
        if t.startswith("uint") or t.startswith("int"):
            norm.append(int(a, 0) if isinstance(a, str) else int(a))
        elif t == "address":
            a = a.strip()
            if not a.startswith("0x") or len(a) != 42:
                raise click.ClickException(f"Invalid address arg: {a}")
            norm.append(a)
        elif t == "bool":
            if isinstance(a, str):
                norm.append(a.lower() in ("1","true","yes","y"))
            else:
                norm.append(bool(a))
        elif t.startswith("bytes") and t != "bytes":
            # bytesN
            h = a.lower().removeprefix("0x")
            norm.append(bytes.fromhex(h))
        elif t == "bytes":
            h = a.lower().removeprefix("0x")
            norm.append(bytes.fromhex(h))
        elif t == "string":
            norm.append(str(a))
        else:
            # naive fallback
            norm.append(a)
    return abi_encode(types, norm)

# ----------------------- raw tx decoder (legacy + 0x02) -----------------------

def _as_int(b: bytes) -> int:
    return 0 if len(b) == 0 else int.from_bytes(b, "big")

def _to_addr(b: bytes) -> Optional[str]:
    if len(b) == 0:
        return None
    if len(b) == 20:
        return to_checksum_address("0x" + b.hex())
    return to_checksum_address("0x" + b[-20:].hex())

def decode_raw_tx(raw_hex: str) -> Dict[str, Any]:
    h = raw_hex.lower()
    if h.startswith("0x"):
        h = h[2:]
    b = bytes.fromhex(h)
    if len(b) == 0:
        raise click.ClickException("Empty tx bytes")

    out = {"type": "legacy", "fields": {}, "calldata": None}

    if b[0] == 0x02:
        payload = b[1:]
        lst = rlp.decode(payload, strict=False)
        if not isinstance(lst, list) or len(lst) < 12:
            raise click.ClickException("Malformed EIP-1559 tx")
        chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList, v, r, s = lst[:12]
        out["type"] = "eip-1559"
        out["fields"] = {
            "chainId": _as_int(chainId),
            "nonce": _as_int(nonce),
            "maxPriorityFeePerGas": _as_int(maxPrio),
            "maxFeePerGas": _as_int(maxFee),
            "gasLimit": _as_int(gas),
            "to": _to_addr(to),
            "value": _as_int(value),
        }
        out["calldata"] = "0x" + data.hex() if len(data) > 0 else None
    else:
        lst = rlp.decode(b, strict=False)
        if not isinstance(lst, list) or len(lst) < 9:
            raise click.ClickException("Malformed legacy tx")
        nonce, gasPrice, gas, to, value, data, v, r, s = lst[:9]
        out["fields"] = {
            "nonce": _as_int(nonce),
            "gasPrice": _as_int(gasPrice),
            "gasLimit": _as_int(gas),
            "to": _to_addr(to),
            "value": _as_int(value),
        }
        out["calldata"] = "0x" + data.hex() if len(data) > 0 else None

    return out

# ----------------------- pledge model -----------------------

@dataclass
class Pledge:
    type: str                 # "txpledge.v1"
    to: Optional[str]         # checksum if possible
    value_wei: Optional[int]
    chain_id: Optional[int]
    function: Dict[str, Any]  # { selector, abi?, types?, args?, data_prefix? }
    policy: Dict[str, Any]    # e.g., { "max_value_wei": ... }
    issued_at: str
    nonce: str
    fingerprint: str          # keccak of canonical pledge (without signature)
    signer: Optional[str]     # 0x.. address of pledge signer
    signature: Optional[str]  # EIP-191 personal_sign over fingerprint

def build_pledge(to: Optional[str], value_wei: Optional[int], chain_id: Optional[int],
                 selector: Optional[str], abi: Optional[str],
                 types: List[str], args: List[str],
                 data_prefix: Optional[str],
                 sign: bool) -> Pledge:
    if abi and not selector:
        selector = sel_from_abi(abi)
    if not selector and not data_prefix:
        raise click.ClickException("Provide either --selector/--abi or --data-prefix.")
    fun: Dict[str, Any] = {}
    if selector:
        fun["selector"] = selector.lower() if selector.startswith("0x") else ("0x" + selector.lower())
    if abi:
        fun["abi"] = abi
    if data_prefix:
        fun["data_prefix"] = data_prefix.lower() if data_prefix.startswith("0x") else ("0x" + data_prefix.lower())
    if types:
        fun["types"] = types
    if args:
        fun["args"] = args
        if types:
            enc = enc_args(types, args)  # may raise if eth-abi missing
            fun["encoded_args_hex"] = "0x" + enc.hex()

    payload = {
        "type": "txpledge.v1",
        "to": as_addr_maybe(to),
        "value_wei": value_wei,
        "chain_id": chain_id,
        "function": fun,
        "policy": {},
        "issued_at": now_iso(),
        "nonce": str(uuid.uuid4()),
    }
    fp = keccak_hex(kjson(payload).encode("utf-8"))

    signer = None
    sig = None
    if sign:
        if not HAVE_SIGN:
            raise click.ClickException("eth-account not installed; cannot sign. See requirements.txt.")
        pk = os.getenv("TXPLEDGE_PRIVKEY", "").strip()
        if not pk:
            raise click.ClickException("Set TXPLEDGE_PRIVKEY=0x... to sign.")
        acct = Account.from_key(pk)
        signer = acct.address
        msg = encode_defunct(text=fp)
        sig = "0x" + acct.sign_message(msg).signature.hex()

    return Pledge(
        type="txpledge.v1",
        to=payload["to"],
        value_wei=value_wei,
        chain_id=chain_id,
        function=fun,
        policy=payload["policy"],
        issued_at=payload["issued_at"],
        nonce=payload["nonce"],
        fingerprint=fp,
        signer=signer,
        signature=sig
    )

# ----------------------- verification -----------------------

def verify_against_tx(pledge: Pledge, raw_tx_hex: str) -> Dict[str, Any]:
    tx = decode_raw_tx(raw_tx_hex)
    f = tx["fields"]
    reasons: List[str] = []
    ok = True

    # to
    if pledge.to and f.get("to") and pledge.to.lower() != f["to"].lower():
        reasons.append(f"to mismatch: pledge {pledge.to} vs tx {f['to']}")
        ok = False
    # value
    pv = pledge.value_wei
    if pv is not None and pv != f.get("value", 0):
        reasons.append(f"value_wei mismatch: pledge {pv} vs tx {f.get('value', 0)}")
        ok = False
    # chain id (only present on 0x02)
    if pledge.chain_id is not None and tx["type"] == "eip-1559":
        if pledge.chain_id != f.get("chainId"):
            reasons.append(f"chainId mismatch: pledge {pledge.chain_id} vs tx {f.get('chainId')}")
            ok = False

    # calldata checks
    data = tx.get("calldata") or ""
    if data:
        if "selector" in pledge.function:
            sel = pledge.function["selector"].lower().removeprefix("0x")
            if data[2:10].lower() != sel:
                reasons.append(f"selector mismatch: pledge 0x{sel} vs tx 0x{data[2:10]}")
                ok = False
        if "encoded_args_hex" in pledge.function:
            pref = (pledge.function["selector"].lower() + pledge.function["encoded_args_hex"].lower().removeprefix("0x")).removeprefix("0x")
            txpref = data.lower().removeprefix("0x")
            if not txpref.startswith(pref):
                reasons.append("encoded args prefix mismatch")
                ok = False
        if "data_prefix" in pledge.function:
            pfx = pledge.function["data_prefix"].lower().removeprefix("0x")
            txpref = (data or "").lower().removeprefix("0x")
            if not txpref.startswith(pfx):
                reasons.append("data prefix mismatch")
                ok = False
    else:
        # If pledge expected a selector but tx has no data
        if "selector" in pledge.function:
            reasons.append("tx has no calldata but pledge expects selector")
            ok = False

    return {
        "match": ok,
        "tx_type": tx["type"],
        "tx_fields": f,
        "tx_calldata": data,
        "fingerprint": pledge.fingerprint,
        "reasons": reasons
    }

# ----------------------- CLI -----------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """txpledge — make a pledge for a transaction and verify raw txs offline."""
    pass

@cli.command("create")
@click.option("--to", type=str, help="Recipient address (0x...).")
@click.option("--value-wei", type=int, default=None, help="Native value in wei.")
@click.option("--chain-id", type=int, default=None, help="Expected chain id (only checked for 0x02 typed tx).")
@click.option("--selector", type=str, default=None, help="Function selector (0x....).")
@click.option("--abi", type=str, default=None, help='Function ABI prototype, e.g. "approve(address,uint256)".')
@click.option("--type", "types_", multiple=True, help="ABI type (repeat per argument) — alternative to --abi parsing.")
@click.option("--arg", "args_", multiple=True, help="Argument value (repeat per argument).")
@click.option("--data-prefix", type=str, default=None, help="Raw data prefix to match (0x...), alternative to --abi/--selector.")
@click.option("--sign", is_flag=True, help="Sign the pledge with TXPLEDGE_PRIVKEY (EIP-191).")
def create_cmd(to, value_wei, chain_id, selector, abi, types_, args_, data_prefix, sign):
    """Create a pledge JSON on stdout."""
    types_list = list(types_)
    args_list = [str(a) for a in args_]
    if abi and types_list and not selector:
        selector = sel_from_abi(abi)
    pledge = build_pledge(to, value_wei, chain_id, selector, abi, types_list, args_list, data_prefix, sign)
    click.echo(json.dumps(asdict(pledge), indent=2))

@cli.command("verify-tx")
@click.argument("pledge_source", type=str)
@click.argument("raw_tx_hex", type=str)
@click.option("--pretty", is_flag=True, help="Human-readable summary.")
def verify_cmd(pledge_source, raw_tx_hex, pretty):
    """Verify RAW_TX_HEX (0x...) against a pledge (file path or inline JSON)."""
    if os.path.isfile(pledge_source):
        with open(pledge_source, "r", encoding="utf-8") as f:
            obj = json.load(f)
    else:
        obj = json.loads(pledge_source)
    pledge = Pledge(**obj)
    rep = verify_against_tx(pledge, raw_tx_hex)
    if pretty:
        status = "MATCH ✅" if rep["match"] else "VIOLATION ❌"
        click.echo(f"txpledge — {status}  fingerprint={rep['fingerprint']}")
        for k in ("to","value","chainId"):
            if k in rep["tx_fields"]:
                click.echo(f"  {k}: {rep['tx_fields'][k]}")
        if rep["tx_calldata"]:
            click.echo(f"  calldata: {rep['tx_calldata'][:66]}...")
        if rep["reasons"]:
            click.echo("  reasons:")
            for r in rep["reasons"]:
                click.echo(f"   - {r}")
    else:
        click.echo(json.dumps(rep, indent=2))
    sys.exit(0 if rep["match"] else 1)

@cli.command("fingerprint")
@click.argument("pledge_source", type=str)
def fp_cmd(pledge_source):
    """Print the canonical fingerprint for a pledge JSON/file."""
    if os.path.isfile(pledge_source):
        with open(pledge_source, "r", encoding="utf-8") as f:
            obj = json.load(f)
    else:
        obj = json.loads(pledge_source)
    # Recompute deterministically from minimal material
    mat = {k: obj[k] for k in ("type","to","value_wei","chain_id","function","policy","issued_at","nonce") if k in obj}
    click.echo(keccak_hex(kjson(mat).encode("utf-8")))

@cli.command("svg-badge")
@click.argument("pledge_source", type=str)
@click.argument("raw_tx_hex", type=str)
@click.option("--out", type=click.Path(writable=True), default="txpledge-badge.svg", show_default=True)
def svg_cmd(pledge_source, raw_tx_hex, out):
    """Write a tiny SVG badge indicating match/violation for a pledge vs tx."""
    if os.path.isfile(pledge_source):
        with open(pledge_source, "r", encoding="utf-8") as f:
            obj = json.load(f)
    else:
        obj = json.loads(pledge_source)
    pledge = Pledge(**obj)
    rep = verify_against_tx(pledge, raw_tx_hex)
    color = "#3fb950" if rep["match"] else "#f85149"
    label = "MATCH" if rep["match"] else "VIOLATION"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="560" height="48" role="img" aria-label="txpledge">
  <rect width="560" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    txpledge: {label}  {rep['fingerprint'][:18]}…
  </text>
  <circle cx="535" cy="24" r="6" fill="{color}"/>
</svg>"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg)
    click.echo(f"Wrote SVG badge: {out}")

if __name__ == "__main__":
    cli()
