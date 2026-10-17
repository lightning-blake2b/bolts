#! /usr/bin/python3
# Independent check of the option_unified_sigs BOLT 3 test vectors.
# Released by Paul Lamb under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/
#
# For every signature in a vector file's commitment and HTLC transactions, it
# recomputes the digest the signature's hash type selects, from the unified
# signature hash as BOLT 3 references it (privkeyio/bitcoin 54d757f269,
# doc/unified-sighash.md), and verifies the signature against the public keys
# in the input's witness script. It shares no code with any implementation:
# secp256k1 and transaction parsing are written out below, using only the
# Python standard library (Python 3.8 or later).
#
# Usage:
#   tools/verify-unified-sighash-vectors.py bolt03/unified-sigs-*-test.json
#
# Prints, per file, how many signatures of each hash type verified, and a
# FAIL line for any that did not. Exits 1 if any signature failed or a file
# held none to check. --tag changes the digest's tag: with any other tag
# every signature should fail, which shows the check is not vacuous.

from optparse import OptionParser
import hashlib
import json
import sys

# secp256k1.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


def parse_pubkey(b):
    """A 33-byte compressed public key."""
    x = int.from_bytes(b[1:], 'big')
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y % 2 != b[0] - 2:
        y = P - y
    return (x, y)


def parse_der(sig):
    if sig[0] != 0x30 or sig[2] != 0x02:
        raise ValueError("not a DER signature")
    rlen = sig[3]
    r = int.from_bytes(sig[4:4 + rlen], 'big')
    slen = sig[5 + rlen]
    s = int.from_bytes(sig[6 + rlen:6 + rlen + slen], 'big')
    return r, s


def ecdsa_verify(pubkey, digest, sig):
    r, s = parse_der(sig)
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(digest, 'big')
    w = pow(s, -1, N)
    pt = point_add(point_mul(z * w % N, G),
                   point_mul(r * w % N, parse_pubkey(pubkey)))
    return pt is not None and pt[0] % N == r


# Transactions.
def compact_size(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def read_compact_size(b, i):
    n = b[i]
    if n < 0xfd:
        return n, i + 1
    if n == 0xfd:
        return int.from_bytes(b[i + 1:i + 3], 'little'), i + 3
    return int.from_bytes(b[i + 1:i + 5], 'little'), i + 5


def parse_tx(hexstr):
    b = bytes.fromhex(hexstr)
    tx = {'version': int.from_bytes(b[0:4], 'little')}
    i = 4
    segwit = b[i] == 0 and b[i + 1] == 1
    if segwit:
        i += 2
    n, i = read_compact_size(b, i)
    tx['ins'] = []
    for _ in range(n):
        prev_txid, vout = b[i:i + 32], int.from_bytes(b[i + 32:i + 36], 'little')
        i += 36
        script_len, i = read_compact_size(b, i)
        i += script_len
        seq = int.from_bytes(b[i:i + 4], 'little')
        i += 4
        tx['ins'].append({'txid': prev_txid, 'vout': vout, 'seq': seq,
                          'witness': []})
    n, i = read_compact_size(b, i)
    tx['outs'] = []
    for _ in range(n):
        value = int.from_bytes(b[i:i + 8], 'little')
        i += 8
        script_len, i = read_compact_size(b, i)
        tx['outs'].append({'value': value, 'spk': b[i:i + script_len]})
        i += script_len
    if segwit:
        for txin in tx['ins']:
            items, i = read_compact_size(b, i)
            for _ in range(items):
                item_len, i = read_compact_size(b, i)
                txin['witness'].append(b[i:i + item_len])
                i += item_len
    tx['locktime'] = int.from_bytes(b[i:i + 4], 'little')
    return tx


def sha256(b):
    return hashlib.sha256(b).digest()


def txid(tx):
    s = tx['version'].to_bytes(4, 'little') + compact_size(len(tx['ins']))
    for txin in tx['ins']:
        s += (txin['txid'] + txin['vout'].to_bytes(4, 'little') + b'\x00' +
              txin['seq'].to_bytes(4, 'little'))
    s += compact_size(len(tx['outs']))
    for out in tx['outs']:
        s += (out['value'].to_bytes(8, 'little') +
              compact_size(len(out['spk'])) + out['spk'])
    s += tx['locktime'].to_bytes(4, 'little')
    return sha256(sha256(s))


def tagged_hash(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def serialize_output(out):
    return (out['value'].to_bytes(8, 'little') +
            compact_size(len(out['spk'])) + out['spk'])


def unified_digest(tx, idx, spent, script_code, hash_type, tag):
    """The unified signature hash of input idx for a segwit v0 script.

    spent holds (value, scriptPubKey) for every input, in order."""
    anyonecanpay = hash_type & 0x80
    base = hash_type & 0x1f
    m = bytes([0, hash_type])
    m += tx['version'].to_bytes(4, 'little')
    m += tx['locktime'].to_bytes(5, 'little')
    if not anyonecanpay:
        m += sha256(b''.join(i['txid'] + i['vout'].to_bytes(4, 'little')
                             for i in tx['ins']))
        m += sha256(b''.join(v.to_bytes(8, 'little', signed=True)
                             for v, _ in spent))
        m += sha256(b''.join(compact_size(len(s)) + s for _, s in spent))
        m += sha256(b''.join(i['seq'].to_bytes(4, 'little')
                             for i in tx['ins']))
    if base not in (2, 3):
        m += sha256(b''.join(serialize_output(o) for o in tx['outs']))
    # Script type 1: a segwit v0 spend.
    m += bytes([1])
    txin = tx['ins'][idx]
    if anyonecanpay:
        value, spk = spent[idx]
        m += (txin['txid'] + txin['vout'].to_bytes(4, 'little') +
              value.to_bytes(8, 'little', signed=True) +
              compact_size(len(spk)) + spk +
              txin['seq'].to_bytes(4, 'little'))
    else:
        m += idx.to_bytes(4, 'little')
    m += compact_size(len(script_code)) + script_code
    if base == 3:
        m += sha256(serialize_output(tx['outs'][idx]))
    return tagged_hash(tag, m)


def script_pubkeys(script):
    """The 33-byte pushes of a script: the keys a signature may be from."""
    keys, i = [], 0
    while i < len(script):
        op = script[i]
        if 1 <= op <= 75:
            if op == 33:
                keys.append(script[i + 1:i + 34])
            i += 1 + op
        else:
            i += 1
    return keys


def check_input(tx, idx, spent, counts, label, tag):
    witness = tx['ins'][idx]['witness']
    script = witness[-1]
    keys = script_pubkeys(script)
    for item in witness[:-1]:
        # Signatures: DER followed by the hash type byte. Other items (the
        # empty CHECKMULTISIG dummy, preimages) are skipped.
        if len(item) < 60 or item[0] != 0x30:
            continue
        hash_type, sig = item[-1], item[:-1]
        digest = unified_digest(tx, idx, spent, script, hash_type, tag)
        counts[hash_type] = counts.get(hash_type, 0) + 1
        if not any(ecdsa_verify(k, digest, sig) for k in keys):
            counts['fail'] = counts.get('fail', 0) + 1
            print("FAIL {}: hash type {:#04x}, digest {}".format(
                label, hash_type, digest.hex()))


# BOLT 3 Appendix C: the funding output every test vector spends.
FUNDING_SATOSHI = 10000000


def check_file(path, tag):
    with open(path) as f:
        cases = json.load(f)
    counts = {}
    for case in cases:
        commitment = parse_tx(case['ExpectedCommitmentTxHex'])
        funding_script = commitment['ins'][0]['witness'][-1]
        funding_spk = b'\x00\x20' + sha256(funding_script)
        check_input(commitment, 0, [(FUNDING_SATOSHI, funding_spk)], counts,
                    case['Name'] + ': commitment', tag)
        commitment_txid = txid(commitment)
        for desc in case.get('HtlcDescs') or []:
            htlc_tx = parse_tx(desc['ResolutionTxHex'])
            txin = htlc_tx['ins'][0]
            if txin['txid'] != commitment_txid:
                raise ValueError("{}: an HTLC transaction does not spend "
                                 "its commitment".format(case['Name']))
            out = commitment['outs'][txin['vout']]
            check_input(htlc_tx, 0, [(out['value'], out['spk'])], counts,
                        "{}: HTLC output {}".format(case['Name'], txin['vout']),
                        tag)
    return counts


def main():
    parser = OptionParser(usage="%prog [--tag TAG] FILE...")
    parser.add_option('--tag', default='UnifiedSighash',
                      help="the digest's tag (default %default)")
    options, files = parser.parse_args()
    if not files:
        parser.error("no vector files given")

    ok = True
    for path in files:
        counts = check_file(path, options.tag)
        fails = counts.pop('fail', 0)
        summary = ', '.join('{} at {:#04x}'.format(n, ht)
                            for ht, n in sorted(counts.items()))
        total = sum(counts.values())
        print("{}: {} signatures ({}): {} verified, {} failed".format(
            path, total, summary or 'none', total - fails, fails))
        if fails or not counts:
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
