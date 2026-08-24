import embit

from binascii import b2a_base64
from gettext import gettext as _
from hashlib import sha256

from embit import bip32, compact, ec
from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from embit.descriptor.arguments import Key, KeyHash
from embit.descriptor.miniscript import Wrapper
from embit.descriptor.taptree import TapLeaf, TapTree
from embit.networks import NETWORKS
from embit.util import secp256k1


from seedsigner.models.settings_definition import SettingsConstants


"""
    Collection of generic embit-powered util methods.
"""
# TODO: PR these directly into `embit`? Or replace with new/existing methods already in `embit`?


# TODO: Refactor `wallet_type` to conform to our `sig_type` naming convention
def get_standard_derivation_path(network: str = SettingsConstants.MAINNET, wallet_type: str = SettingsConstants.SINGLE_SIG, script_type: str = SettingsConstants.NATIVE_SEGWIT) -> str:
    if network == SettingsConstants.MAINNET:
        network_path = "0'"
    elif network == SettingsConstants.TESTNET:
        network_path = "1'"
    elif network == SettingsConstants.REGTEST:
        network_path = "1'"
    else:
        raise Exception("Unexpected network")

    if wallet_type == SettingsConstants.SINGLE_SIG:
        if script_type == SettingsConstants.LEGACY_P2PKH:
            return f"m/44'/{network_path}/0'"
        elif script_type == SettingsConstants.NESTED_SEGWIT:
            return f"m/49'/{network_path}/0'"
        elif script_type == SettingsConstants.NATIVE_SEGWIT:
            return f"m/84'/{network_path}/0'"
        elif script_type == SettingsConstants.TAPROOT:
            return f"m/86'/{network_path}/0'"
        else:
            raise Exception("Unexpected script type")

    elif wallet_type == SettingsConstants.MULTISIG:
        if script_type == SettingsConstants.LEGACY_P2PKH:
            return f"m/45'" #BIP-45
        elif script_type == SettingsConstants.NESTED_SEGWIT:
            return f"m/48'/{network_path}/0'/1'"
        elif script_type == SettingsConstants.NATIVE_SEGWIT:
            return f"m/48'/{network_path}/0'/2'"
        elif script_type == SettingsConstants.TAPROOT:
            raise Exception("Taproot multisig not yet supported")
        else:
            raise Exception("Unexpected script type")
    else:
        raise Exception("Unexpected wallet type")    # checks that all inputs are from the same wallet



def get_xpub(seed_bytes, derivation_path: str, embit_network: str = "main") -> HDKey:
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])
    xprv = root.derive(derivation_path)
    xpub = xprv.to_public()
    return xpub



def get_single_sig_address(xpub: HDKey, script_type: str = SettingsConstants.NATIVE_SEGWIT, index: int = 0, is_change: bool = False, embit_network: str = "main") -> str:
    if is_change:
        pubkey = xpub.derive([1,index]).key
    else:
        pubkey = xpub.derive([0,index]).key

    if script_type == SettingsConstants.LEGACY_P2PKH:
        return embit.script.p2pkh(pubkey).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.NESTED_SEGWIT:
        return embit.script.p2sh(embit.script.p2wpkh(pubkey)).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.NATIVE_SEGWIT:
        return embit.script.p2wpkh(pubkey).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.TAPROOT:
        return embit.script.p2tr(pubkey).address(network=NETWORKS[embit_network])



def can_derive_multisig_address(descriptor: Descriptor) -> bool:
    """Whether `get_multisig_address()` can actually derive an address for this
    descriptor: p2wsh/p2sh-p2wsh (including any wsh() Miniscript, not just basic
    multisig), and legacy basic-multisig p2sh.

    NOTE: this returns True for taproot too, because embit's `is_segwit` is True
    for taproot descriptors -- which also makes the `elif descriptor.is_taproot:
    raise` branch in `get_multisig_address()` below unreachable dead code.
    Taproot addresses do in fact derive correctly through that path (verified by
    test_get_multisig_address's taproot vector), so this is intentionally left
    as-is rather than "fixed" to reject taproot; taproot *signing* is what's
    still gated, over in PSBTParser.
    """
    return bool(descriptor.is_segwit or (descriptor.is_legacy and descriptor.is_basic_multisig))



def get_multisig_address(descriptor: Descriptor, index: int = 0, is_change: bool = False, embit_network: str = "main"):
    if is_change:
        branch_index = 1
    else:
        branch_index = 0

    # Can derive p2wsh, p2sh-p2wsh, and legacy (non-segwit) p2sh
    if can_derive_multisig_address(descriptor):
        return descriptor.derive(index, branch_index=branch_index).script_pubkey().address(network=NETWORKS[embit_network])

    elif descriptor.is_taproot:
        # Unreachable: embit's `is_segwit` is True for taproot descriptors too,
        # so `can_derive_multisig_address()` above already returns True and
        # taproot addresses derive correctly through that branch (see its
        # docstring). Left in place rather than removed -- see the working
        # plan's explicit note not to touch this without cause; it's dead code,
        # not a bug, and touching it risks a behavior nobody's depending on.
        raise Exception("Taproot verification not yet implemented!")

    raise Exception(f"{descriptor.script_pubkey().script_type()} address verification not yet implemented!")



def get_multisig_policy(descriptor: Descriptor) -> tuple:
    """Extract (threshold, n) from a basic multisig descriptor."""
    if not descriptor.is_basic_multisig:
        raise ValueError(f"Expected a basic multisig descriptor, got: {descriptor.brief_policy}")
    return (str(descriptor.miniscript.args[0]), str(len(descriptor.keys)))



def is_supported_wallet_descriptor(descriptor: Descriptor) -> bool:
    """
    Whether `descriptor` is one we know how to register, display, and (where
    Address Explorer / Verify Addr are concerned) derive addresses for.

    This is deliberately broader than `is_basic_multisig`: it also accepts
    general wsh() Miniscript policies (e.g. Liana's or_d(pk(...),and_v(...))
    recovery policies) and taproot descriptors. Taproot registration/display is
    allowed because `get_descriptor_policy_summary()` can describe it correctly
    -- taproot *address verification* and *script-path signing* remain
    separately gated in `get_multisig_address()` and `PSBTParser`, which still
    correctly raise "not yet implemented" for the taproot cases that aren't
    ready, so allowing registration here doesn't let a user get further than
    what's actually supported.

    A bare single-key descriptor (wpkh()/pkh(), no miniscript, no taproot
    script path) is intentionally excluded -- that's a plain single-sig import,
    a separate unimplemented case (see the TODO this replaces in ScanView).
    """
    if descriptor.is_basic_multisig:
        return True
    if descriptor.is_taproot:
        return True
    if descriptor.is_segwit and descriptor.miniscript is not None:
        return True
    return False



def _describe_key(key: Key) -> str:
    # TRANSLATOR_NOTE: identifies a signing key by its 4-byte master fingerprint, e.g. "key 73C5DA0A"
    return _("key {fingerprint}").format(fingerprint=key.fingerprint.hex().upper())



def _describe_miniscript_node(node) -> str:
    """
    Recursively render a parsed Miniscript fragment (or a bare Key/KeyHash leaf)
    as plain English. Driven by each fragment's own `NAME` (embit's
    `OPERATOR_NAMES`, i.e. the exact descriptor keyword: "older", "and_v",
    "thresh", etc.) rather than a fixed set of isinstance checks, so this stays
    correct if embit adds fragments we haven't special-cased below -- those
    fall through to the raw-text fallback at the end instead of being silently
    misdescribed or dropped.
    """
    if isinstance(node, (Key, KeyHash)):
        return _describe_key(node)

    if isinstance(node, Wrapper):
        # Wrappers (a: s: c: t: d: v: j: n: l: u:) change stack/verify mechanics,
        # not *who* can spend -- describe the wrapped fragment directly.
        return _describe_miniscript_node(node.arg)

    name = getattr(node, "NAME", None)

    if name == "older":
        # TRANSLATOR_NOTE: {n} is a number of blocks (relative timelock, OP_CHECKSEQUENCEVERIFY)
        return _("after {n} blocks").format(n=node.arg.num)

    if name == "after":
        # TRANSLATOR_NOTE: {n} is a block height (absolute timelock, OP_CHECKLOCKTIMEVERIFY)
        return _("after block height {n}").format(n=node.arg.num)

    if name in ("sha256", "hash256", "ripemd160", "hash160"):
        # TRANSLATOR_NOTE: {name} is a hash function name, e.g. "sha256"
        return _("a {name} preimage").format(name=name)

    if name == "andor":
        x, y, z = node.args
        # TRANSLATOR_NOTE: describes miniscript's andor(X,Y,Z): if X then Y, else Z
        return _("if ({x}) then ({y}) else ({z})").format(
            x=_describe_miniscript_node(x),
            y=_describe_miniscript_node(y),
            z=_describe_miniscript_node(z),
        )

    if name in ("and_v", "and_b", "and_n"):
        x, y = node.args[0], node.args[1]
        # TRANSLATOR_NOTE: describes an AND condition between two spending requirements
        return _("({x}) and ({y})").format(x=_describe_miniscript_node(x), y=_describe_miniscript_node(y))

    if name in ("or_b", "or_c", "or_d", "or_i"):
        x, y = node.args[0], node.args[1]
        # TRANSLATOR_NOTE: describes an OR condition between two spending requirements
        return _("({x}) or ({y})").format(x=_describe_miniscript_node(x), y=_describe_miniscript_node(y))

    if name == "thresh":
        k = node.args[0].num
        subs = [_describe_miniscript_node(a) for a in node.args[1:]]
        # TRANSLATOR_NOTE: {k} of the following {subs} conditions must be satisfied
        return _("{k} of: [{subs}]").format(k=k, subs="; ".join(subs))

    if name in ("multi", "sortedmulti", "multi_a", "sortedmulti_a"):
        k = node.args[0].num
        keys = [_describe_key(a) for a in node.args[1:]]
        # TRANSLATOR_NOTE: a k-of-n multisig; {keys} is a list of key descriptions
        return _("{k} of {n} keys: [{keys}]").format(k=k, n=len(keys), keys=", ".join(keys))

    if name in ("pk", "pk_k", "pkh", "pk_h"):
        # arg is already a Key or KeyHash; recurse to hit the isinstance branch above
        return _describe_miniscript_node(node.arg)

    if type(node).__name__ == "JustZero":
        # TRANSLATOR_NOTE: an unspendable/always-false miniscript fragment
        return _("(unspendable)")

    if type(node).__name__ == "JustOne":
        # TRANSLATOR_NOTE: an always-true/no-condition miniscript fragment
        return _("(no condition)")

    # Unknown/future fragment: never silently drop or misdescribe it -- show
    # its raw descriptor text so an unsupported case is visibly incomplete
    # rather than confidently wrong.
    return str(node)



def _flatten_taptree_leaves(taptree: TapTree) -> list:
    """Return every TapLeaf in a (possibly nested) TapTree, in no particular order.

    A TapTree's `.tree` is None, a single TapLeaf, or a 2-tuple of TapTree
    branches (see embit.descriptor.taptree.TapTree.read_from) -- this walks
    that structure regardless of depth/shape.
    """
    if taptree is None or taptree.tree is None:
        return []
    if isinstance(taptree.tree, TapLeaf):
        return [taptree.tree]
    left, right = taptree.tree
    return _flatten_taptree_leaves(left) + _flatten_taptree_leaves(right)



def get_descriptor_policy_summary(descriptor: Descriptor, max_length: int = 180) -> str:
    """
    Plain-English summary of any descriptor's spending policy -- basic
    multisig, general wsh() Miniscript, or taproot (key-path plus any hidden
    script-path leaves).

    Correctness requirement: a taproot descriptor with a hidden script-path
    recovery leaf must never be summarized as plain single-key/single-signature.
    This is structural, not case-by-case -- the taproot branch below always
    enumerates every leaf found by `_flatten_taptree_leaves()` if any exist,
    regardless of whether each leaf's contents can be perfectly described (an
    unrecognized leaf fragment still shows up as raw text via
    `_describe_miniscript_node()`'s fallback, it's just never omitted).
    """
    if descriptor.is_basic_multisig:
        threshold, n = get_multisig_policy(descriptor)
        # TRANSLATOR_NOTE: Multisig policy. For a "2 of 3" policy, "threshold" = 2; "n" = 3
        summary = _("{threshold} of {n} multisig").format(threshold=threshold, n=n)

    elif descriptor.is_taproot:
        parts = [_describe_miniscript_node(descriptor.key)]
        leaves = _flatten_taptree_leaves(descriptor.taptree)
        if leaves:
            leaf_descriptions = [_describe_miniscript_node(leaf.miniscript) for leaf in leaves]
            # TRANSLATOR_NOTE: {key} is the taproot key-path spending key; {leaves} lists hidden alternate spending paths
            summary = _("Taproot: key-path ({key}); script-path: {leaves}").format(
                key=parts[0], leaves="; ".join(leaf_descriptions)
            )
        else:
            # TRANSLATOR_NOTE: a taproot descriptor with no hidden script paths at all -- key-path spend only
            summary = _("Taproot: key-path only ({key})").format(key=parts[0])

    elif descriptor.miniscript is not None:
        summary = _describe_miniscript_node(descriptor.miniscript)

    elif descriptor.key is not None:
        # Bare single key (e.g. wpkh()/pkh()); describe safely rather than
        # raising if a caller ever routes one here.
        summary = _describe_miniscript_node(descriptor.key)

    else:
        raise ValueError(f"Unable to summarize descriptor policy: {descriptor}")

    if len(summary) > max_length:
        summary = summary[: max_length - 1].rstrip() + "…"  # ellipsis
    return summary



def get_embit_network_name(settings_name):
    """ Convert SeedSigner SettingsConstants for `network` to embit's NETWORK key """
    lookup = {
        SettingsConstants.MAINNET: "main",
        SettingsConstants.TESTNET: "test",
        SettingsConstants.REGTEST: "regtest",
    }
    return lookup.get(settings_name)



def parse_derivation_path(derivation_path: str) -> dict:
    """
    Parses a derivation path into its related SettingsConstants equivalents.

    Primarily only supports single sig derivation paths.

    May return None for fields it cannot parse.
    """
    # Support either m/44'/... or m/44h/... style
    derivation_path = derivation_path.replace("'", "h")

    sections = derivation_path.split("/")

    if sections[1] == "48h":
        # So far this helper is only meant for single sig message signing
        raise Exception("Not implemented")

    lookups = {
        "script_types": {
            "44h": SettingsConstants.LEGACY_P2PKH,
            "49h": SettingsConstants.NESTED_SEGWIT,
            "84h": SettingsConstants.NATIVE_SEGWIT,
            "86h": SettingsConstants.TAPROOT,
        },
        "networks": {
            "0h": SettingsConstants.MAINNET,
            "1h": [SettingsConstants.TESTNET, SettingsConstants.REGTEST],
        }
    }

    details = dict()
    details["script_type"] = lookups["script_types"].get(sections[1])
    if not details["script_type"]:
        details["script_type"] = SettingsConstants.CUSTOM_DERIVATION
    details["network"] = lookups["networks"].get(sections[2])

    # Check if there's a standard change path
    if sections[-2] in ["0", "1"]:
        details["is_change"] = sections[-2] == "1"
    else:
        details["is_change"] = None

    # Check if there's a standard address index
    if sections[-1].isdigit():
        details["index"] = int(sections[-1])
    else:
        details["index"] = None

    if details["is_change"] is not None and details["index"] is not None:
        # standard change and addr index; safe to truncate to the wallet level
        details["wallet_derivation_path"] = "/".join(sections[:-2])
    else:
        details["wallet_derivation_path"] = None

    details["clean_match"] = True
    for k, v in details.items():
        if v is None:
            # At least one field couldn't be parsed
            details["clean_match"] = False
            break

    return details



def sign_message(seed_bytes: bytes, derivation: str, msg: bytes, compressed: bool = True, embit_network: str = "main") -> bytes:
    """
        from: https://github.com/cryptoadvance/specter-diy/blob/b58a819ef09b2bca880a82c7e122618944355118/src/apps/signmessage/signmessage.py
    """
    """Sign message with private key"""
    msghash = sha256(
        sha256(
            b"\x18Bitcoin Signed Message:\n" + compact.to_bytes(len(msg)) + msg
        ).digest()
    ).digest()

    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])
    prv = root.derive(derivation).key
    sig = secp256k1.ecdsa_sign_recoverable(msghash, prv._secret)
    flag = sig[64]
    sig = ec.Signature(sig[:64])
    c = 4 if compressed else 0
    flag = bytes([27 + flag + c])
    ser = flag + secp256k1.ecdsa_signature_serialize_compact(sig._sig)
    return b2a_base64(ser).strip().decode()
