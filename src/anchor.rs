//! Merkle anchoring over receipt `content_hash`es, verifiable offline with no Tectic code.
//!
//! One RFC 3161 timestamp over a Merkle root timestamps every receipt under it. Construction:
//!
//! - leaf  = SHA-256(0x00 || UTF-8 bytes of the receipt's `content_hash` hex string)
//! - node  = SHA-256(0x01 || left || right)
//! - The 0x00 / 0x01 prefixes separate leaves from nodes, so an inner node can never be
//!   presented as a leaf (second-preimage defence).
//! - Level by level, left to right. An odd node at the end of a level is promoted to the next
//!   level unchanged (never duplicated, so `[a,b,c]` and `[a,b,c,c]` have different roots).
//! - Root of one leaf = that leaf. The empty tree has no root ([`root`] returns `None`).
//!
//! An inclusion proof is the sibling hashes from leaf to root, skipping promoted levels. The
//! verifier takes `index` and `leaf_count` and re-derives which side every sibling is on, so a
//! proof cannot be replayed at another position or tree size.
//! The root does not itself commit to `leaf_count`; the anchor record carries it next to the root.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::receipt::ExecutionReceipt;

pub type Hash = [u8; 32];

pub fn leaf_hash(content_hash: &str) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(content_hash.as_bytes());
    h.finalize().into()
}

fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn next_level(level: &[Hash]) -> Vec<Hash> {
    level
        .chunks(2)
        .map(|p| {
            if p.len() == 2 {
                node_hash(&p[0], &p[1])
            } else {
                p[0]
            }
        })
        .collect()
}

/// Merkle root over the receipts' content hashes, in order. `None` for no leaves.
pub fn root(content_hashes: &[&str]) -> Option<Hash> {
    let mut level: Vec<Hash> = content_hashes.iter().map(|c| leaf_hash(c)).collect();
    if level.is_empty() {
        return None;
    }
    while level.len() > 1 {
        level = next_level(&level);
    }
    Some(level[0])
}

/// Sibling hashes (leaf to root) proving leaf `index` is under [`root`]. `None` if out of range.
pub fn inclusion_proof(content_hashes: &[&str], index: usize) -> Option<Vec<Hash>> {
    if index >= content_hashes.len() {
        return None;
    }
    let mut level: Vec<Hash> = content_hashes.iter().map(|c| leaf_hash(c)).collect();
    let (mut idx, mut out) = (index, Vec::new());
    while level.len() > 1 {
        let sib = idx ^ 1;
        if sib < level.len() {
            out.push(level[sib]);
        }
        level = next_level(&level);
        idx /= 2;
    }
    Some(out)
}

/// True iff `content_hash` is leaf `index` of a `leaf_count`-leaf tree with root `expected`.
pub fn verify_inclusion(
    content_hash: &str,
    index: usize,
    leaf_count: usize,
    siblings: &[Hash],
    expected: &Hash,
) -> bool {
    if index >= leaf_count {
        return false;
    }
    let (mut idx, mut n, mut acc) = (index, leaf_count, leaf_hash(content_hash));
    let mut sibs = siblings.iter();
    while n > 1 {
        if idx % 2 == 1 {
            let Some(s) = sibs.next() else { return false };
            acc = node_hash(s, &acc);
        } else if idx + 1 < n {
            let Some(s) = sibs.next() else { return false };
            acc = node_hash(&acc, s);
        } // else: promoted unchanged
        idx /= 2;
        n = n.div_ceil(2);
    }
    sibs.next().is_none() && &acc == expected
}

/// Schema tag of [`ProofDoc`], the file `reede anchor verify --proof` reads.
pub const PROOF_SCHEMA: &str = "reede-byoa-proof-v1";

/// Domain tag of [`anchor_digest`].
pub const ANCHOR_DOMAIN: &[u8] = b"reede-anchor-v1";

/// The 32 bytes an RFC 3161 token must cover for an anchor (its message imprint, SHA-256):
///
/// `SHA-256("reede-anchor-v1" || 0x00 || chain_key || 0x00 || from_seq_be64 || to_seq_be64
///  || leaf_count_be64 || merkle_root)`
///
/// `chain_key` is UTF-8 (it must not contain NUL), the three counters are 8-byte big-endian,
/// `merkle_root` is the raw 32 bytes. Binding the chain and range stops a token for one
/// tenant's root from being shown as the anchor of another chain or range.
pub fn anchor_digest(
    chain_key: &str,
    from_seq: u64,
    to_seq: u64,
    leaf_count: u64,
    merkle_root: &Hash,
) -> Hash {
    let mut h = Sha256::new();
    h.update(ANCHOR_DOMAIN);
    h.update([0x00]);
    h.update(chain_key.as_bytes());
    h.update([0x00]);
    h.update(from_seq.to_be_bytes());
    h.update(to_seq.to_be_bytes());
    h.update(leaf_count.to_be_bytes());
    h.update(merkle_root);
    h.finalize().into()
}

/// The anchor's digest as hex; `None` if the root is malformed or `chain_key` holds a NUL
/// (which would make the encoding ambiguous).
pub fn entry_digest_hex(chain_key: &str, a: &AnchorEntry) -> Option<String> {
    if chain_key.contains('\0') {
        return None;
    }
    let root = decode_hash(&a.merkle_root)?;
    Some(hex::encode(anchor_digest(
        chain_key,
        a.from_seq,
        a.to_seq,
        u64::try_from(a.leaf_count).ok()?,
        &root,
    )))
}

/// Operator-facing label for the timestamp authority, shown wherever an anchor is presented.
/// `tsa_qualified` is operator-asserted in the proof file; nothing here checks it.
pub fn tsa_label(qualified: bool) -> &'static str {
    if qualified {
        "claimed qualified"
    } else {
        "interim, not qualified"
    }
}

/// Inclusion of one receipt in an anchor's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inclusion {
    pub sequence_no: u64,
    /// Zero-based position among the anchor's leaves (receipts `from_seq..=to_seq` in order).
    pub index: usize,
    /// Hex sibling hashes, leaf to root.
    pub siblings: Vec<String>,
}

/// One anchor row: a Merkle root over receipts `from_seq..=to_seq` and its timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEntry {
    pub from_seq: u64,
    pub to_seq: u64,
    pub leaf_count: usize,
    pub merkle_root: String,
    pub tsa_url: String,
    pub tsa_qualified: bool,
    /// Base64 RFC 3161 token (or response) whose imprint is [`anchor_digest`] of this anchor;
    /// absent while pending.
    #[serde(default)]
    pub tsa_token: Option<String>,
    /// `pending`, `anchored` or `failed`.
    pub status: String,
    #[serde(default)]
    pub anchored_at: Option<String>,
    /// Inclusion proofs for the receipts of the slice this anchor covers.
    #[serde(default)]
    pub inclusion: Vec<Inclusion>,
}

/// The whole proof: a chain slice, the anchors over it and the signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofDoc {
    pub schema: String,
    /// `reported` or `witnessed`.
    pub chain: String,
    pub chain_key: String,
    pub pubkey_hex: String,
    pub receipts: Vec<ExecutionReceipt>,
    pub anchors: Vec<AnchorEntry>,
}

/// Inclusion proofs for the `wanted` sequence numbers of an anchor whose leaves are
/// `leaves` = `(sequence_no, content_hash)` for `from_seq..=to_seq`, in order.
pub fn inclusions(leaves: &[(u64, &str)], wanted: &[u64]) -> Vec<Inclusion> {
    let hashes: Vec<&str> = leaves.iter().map(|(_, h)| *h).collect();
    wanted
        .iter()
        .filter_map(|seq| {
            let index = leaves.iter().position(|(s, _)| s == seq)?;
            let siblings = inclusion_proof(&hashes, index)?;
            Some(Inclusion {
                sequence_no: *seq,
                index,
                siblings: siblings.iter().map(hex::encode).collect(),
            })
        })
        .collect()
}

/// Check one inclusion against an anchor's root; `false` on any malformed hex.
pub fn inclusion_ok(entry: &AnchorEntry, inc: &Inclusion, content_hash: &str) -> bool {
    let Some(root) = decode_hash(&entry.merkle_root) else {
        return false;
    };
    let sibs: Option<Vec<Hash>> = inc.siblings.iter().map(|s| decode_hash(s)).collect();
    sibs.is_some_and(|s| verify_inclusion(content_hash, inc.index, entry.leaf_count, &s, &root))
}

fn decode_hash(s: &str) -> Option<Hash> {
    hex::decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| hex::encode(Sha256::digest(format!("receipt-{i}"))))
            .collect()
    }

    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn every_leaf_of_every_size_proves_inclusion() {
        for n in [1usize, 2, 3, 7, 1000] {
            let h = hashes(n);
            let r = refs(&h);
            let rt = root(&r).unwrap();
            let step = if n > 50 { 37 } else { 1 };
            for i in (0..n).step_by(step).chain([n - 1]) {
                let p = inclusion_proof(&r, i).unwrap();
                assert!(verify_inclusion(r[i], i, n, &p, &rt), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn one_leaf_root_is_the_leaf_and_empty_has_none() {
        let h = hashes(1);
        assert_eq!(root(&refs(&h)).unwrap(), leaf_hash(&h[0]));
        assert!(root(&[]).is_none());
        assert!(inclusion_proof(&refs(&h), 1).is_none());
    }

    #[test]
    fn altered_leaf_sibling_index_root_or_shape_fail() {
        for n in [2usize, 3, 7, 1000] {
            let h = hashes(n);
            let r = refs(&h);
            let rt = root(&r).unwrap();
            let i = n - 1;
            let p = inclusion_proof(&r, i).unwrap();
            assert!(verify_inclusion(r[i], i, n, &p, &rt));
            assert!(!verify_inclusion("00", i, n, &p, &rt), "altered leaf n={n}");
            let mut bad = p.clone();
            bad[0][0] ^= 1;
            assert!(
                !verify_inclusion(r[i], i, n, &bad, &rt),
                "altered sibling n={n}"
            );
            assert!(!verify_inclusion(r[i], 0, n, &p, &rt), "wrong index n={n}");
            assert!(!verify_inclusion(r[i], n, n, &p, &rt), "out of range n={n}");
            let mut wrong = rt;
            wrong[31] ^= 1;
            assert!(
                !verify_inclusion(r[i], i, n, &p, &wrong),
                "wrong root n={n}"
            );
            assert!(!verify_inclusion(r[i], i, n, &p[1..], &rt), "short n={n}");
            let mut long = p.clone();
            long.push([0; 32]);
            assert!(!verify_inclusion(r[i], i, n, &long, &rt), "long n={n}");
        }
    }

    #[test]
    fn odd_node_is_promoted_not_duplicated() {
        let h = hashes(3);
        let dup = vec![h[0].clone(), h[1].clone(), h[2].clone(), h[2].clone()];
        assert_ne!(root(&refs(&h)), root(&refs(&dup)));
    }

    /// Pinned vectors (also in docs/anchor.md): a third party can recompute these by hand.
    #[test]
    fn published_vectors() {
        let h = hashes(3);
        assert_eq!(
            hex::encode(root(&refs(&h)).unwrap()),
            "d377bb2325e44396318a28cc6e82831aa1654b41334dd79b4a4cd8662e2ea94c"
        );
        assert_eq!(
            hex::encode(leaf_hash(&h[0])),
            "5bd146667a0858414c27892ff78455d2107d1432c505d8f26311acf51c85e735"
        );
        let d = anchor_digest("acme#byoa", 1, 3, 3, &root(&refs(&h)).unwrap());
        assert_eq!(
            hex::encode(d),
            "a1e7f856860824a193192cbbdadaf8edff2c19d91cd9f749ea71f6c98aadb794"
        );
    }

    #[test]
    fn the_digest_binds_chain_range_count_and_root() {
        let r = root(&refs(&hashes(3))).unwrap();
        let base = anchor_digest("acme#byoa", 1, 3, 3, &r);
        assert_ne!(base, anchor_digest("globex#byoa", 1, 3, 3, &r));
        assert_ne!(base, anchor_digest("acme#byoa", 2, 3, 3, &r));
        assert_ne!(base, anchor_digest("acme#byoa", 1, 4, 3, &r));
        assert_ne!(base, anchor_digest("acme#byoa", 1, 3, 4, &r));
        assert_ne!(base, anchor_digest("acme#byoa", 1, 3, 3, &[0; 32]));
        assert_ne!(base, r);
    }

    #[test]
    fn an_inner_node_is_not_a_leaf() {
        let h = hashes(2);
        let rt = root(&refs(&h)).unwrap();
        assert_ne!(leaf_hash(&hex::encode(rt)), rt);
    }
}
