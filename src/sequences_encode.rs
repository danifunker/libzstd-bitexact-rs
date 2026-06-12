//! Sequences-section encoder: `ZSTD_seqToCodes`, `ZSTD_selectEncodingType`,
//! `ZSTD_buildCTable` (the sequences flavor), `ZSTD_encodeSequences`, and the
//! `ZSTD_entropyCompressSeqStore` shell that assembles a whole
//! `Compressed_Block` body (literals section + sequences section). Ports of
//! `zstd_compress_sequences.c` and the corresponding parts of
//! `zstd_compress.c` (bundled zstd 1.5.7).
//!
//! 64-bit specialization: the C encode loop's `MEM_32bits()` branches are
//! dropped, and `longOffsets` is structurally impossible (it requires an
//! offset code ≥ `STREAM_ACCUMULATOR_MIN` = 57 on 64-bit, while the format
//! caps offset codes at 31 — C asserts exactly this).
#![allow(dead_code)]
// Wired into the public compressor in M4.2.
// Symbol loops index `count`/`norm` in lockstep with the C originals; keeping
// the index form preserves the line-by-line correspondence.
#![allow(clippy::needless_range_loop)]

use crate::block::{
    LL_BITS, LL_DEFAULT_LOG, LL_DEFAULT_NORM, ML_BITS, ML_DEFAULT_LOG, ML_DEFAULT_NORM,
    OF_DEFAULT_LOG, OF_DEFAULT_NORM,
};
use crate::error::Error;
use crate::fse_encode::{self, BitCStream, FseCTable, Normalized};
use crate::literals_encode;

pub(crate) const MAX_LL: u32 = 35;
pub(crate) const MAX_ML: u32 = 52;
pub(crate) const MAX_OFF: u32 = 31;
/// `MaxSeq`: the largest sequence code of any kind.
pub(crate) const MAX_SEQ: usize = 52;
/// `DefaultMaxOff`: the predefined offset table only covers codes 0..=28.
const DEFAULT_MAX_OFF: u32 = 28;
const LL_FSE_LOG: u32 = 9;
const ML_FSE_LOG: u32 = 9;
const OFF_FSE_LOG: u32 = 8;
const LONG_NB_SEQ: usize = 0x7F00;
pub(crate) const MIN_MATCH: u32 = 3;

fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

// --- SeqStore ---------------------------------------------------------------

/// One stored sequence (`SeqDef`): `off_base` is the offset code base — the
/// real offset + 3 for ordinary matches, or 1..=3 for repeat-offset codes;
/// `lit_length` and `ml_base` (= match length − MINMATCH) are the truncated
/// 16-bit fields, with the long-length marker covering the rare overflow.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeqDef {
    pub off_base: u32,
    pub lit_length: u16,
    pub ml_base: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LongLengthType {
    None,
    LiteralLength,
    MatchLength,
}

/// The compressor-side sequence store (`SeqStore_t`): literals accumulated in
/// one buffer plus the sequence triples that reference them.
pub(crate) struct SeqStore {
    pub literals: Vec<u8>,
    pub sequences: Vec<SeqDef>,
    pub long_length_type: LongLengthType,
    pub long_length_pos: u32,
}

impl SeqStore {
    pub(crate) fn new() -> Self {
        SeqStore {
            literals: Vec::new(),
            sequences: Vec::new(),
            long_length_type: LongLengthType::None,
            long_length_pos: 0,
        }
    }

    /// `ZSTD_storeSeq`: append `literals` and one sequence. `off_base` uses the
    /// same convention as `SeqDef`; `match_len` is the real match length.
    /// Lengths beyond 16 bits set the (single) long-length marker, exactly as
    /// the C store does.
    pub(crate) fn store_seq(&mut self, literals: &[u8], off_base: u32, match_len: u32) {
        let lit_length = literals.len();
        self.literals.extend_from_slice(literals);
        if lit_length > 0xFFFF {
            debug_assert_eq!(self.long_length_type, LongLengthType::None);
            self.long_length_type = LongLengthType::LiteralLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        let ml_base = match_len - MIN_MATCH;
        if ml_base > 0xFFFF {
            debug_assert_eq!(self.long_length_type, LongLengthType::None);
            self.long_length_type = LongLengthType::MatchLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        self.sequences.push(SeqDef {
            off_base,
            lit_length: lit_length as u16,
            ml_base: ml_base as u16,
        });
    }

    /// `ZSTD_storeLastLiterals`: trailing literals after the final sequence.
    pub(crate) fn store_last_literals(&mut self, literals: &[u8]) {
        self.literals.extend_from_slice(literals);
    }
}

// --- seqToCodes --------------------------------------------------------------

/// `ZSTD_LLcode`.
pub(crate) fn ll_code(lit_length: u32) -> u8 {
    #[rustfmt::skip]
    const LL_CODE: [u8; 64] = [
         0,  1,  2,  3,  4,  5,  6,  7,
         8,  9, 10, 11, 12, 13, 14, 15,
        16, 16, 17, 17, 18, 18, 19, 19,
        20, 20, 20, 20, 21, 21, 21, 21,
        22, 22, 22, 22, 22, 22, 22, 22,
        23, 23, 23, 23, 23, 23, 23, 23,
        24, 24, 24, 24, 24, 24, 24, 24,
        24, 24, 24, 24, 24, 24, 24, 24,
    ];
    const LL_DELTA_CODE: u32 = 19;
    if lit_length > 63 {
        (highbit32(lit_length) + LL_DELTA_CODE) as u8
    } else {
        LL_CODE[lit_length as usize]
    }
}

/// `ZSTD_MLcode` (`ml_base` = match length − MINMATCH).
pub(crate) fn ml_code(ml_base: u32) -> u8 {
    #[rustfmt::skip]
    const ML_CODE: [u8; 128] = [
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
        38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
        41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    ];
    const ML_DELTA_CODE: u32 = 36;
    if ml_base > 127 {
        (highbit32(ml_base) + ML_DELTA_CODE) as u8
    } else {
        ML_CODE[ml_base as usize]
    }
}

/// `ZSTD_seqToCodes`: produce the per-sequence LL/OF/ML code tables, applying
/// the long-length overrides. (On 64-bit, `longOffsets` is always false.)
fn seq_to_codes(store: &SeqStore) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let nb_seq = store.sequences.len();
    let mut ll = Vec::with_capacity(nb_seq);
    let mut of = Vec::with_capacity(nb_seq);
    let mut ml = Vec::with_capacity(nb_seq);
    for s in &store.sequences {
        ll.push(ll_code(u32::from(s.lit_length)));
        of.push(highbit32(s.off_base) as u8);
        ml.push(ml_code(u32::from(s.ml_base)));
    }
    match store.long_length_type {
        LongLengthType::LiteralLength => ll[store.long_length_pos as usize] = MAX_LL as u8,
        LongLengthType::MatchLength => ml[store.long_length_pos as usize] = MAX_ML as u8,
        LongLengthType::None => {}
    }
    (ll, of, ml)
}

// --- Encoding-type selection --------------------------------------------------

/// `SymbolEncodingType_e`, in the on-wire numbering.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SymbolEncodingType {
    Basic = 0,
    Rle = 1,
    Compressed = 2,
    Repeat = 3,
}

/// `FSE_repeat`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum FseRepeat {
    #[default]
    None,
    Check,
    Valid,
}

/// `-log2(x/256)` lookup in 1/256th-bit units (`kInverseProbabilityLog256`).
#[rustfmt::skip]
const K_INVERSE_PROBABILITY_LOG256: [u32; 256] = [
    0,    2048, 1792, 1642, 1536, 1453, 1386, 1329, 1280, 1236, 1197, 1162,
    1130, 1100, 1073, 1047, 1024, 1001, 980,  960,  941,  923,  906,  889,
    874,  859,  844,  830,  817,  804,  791,  779,  768,  756,  745,  734,
    724,  714,  704,  694,  685,  676,  667,  658,  650,  642,  633,  626,
    618,  610,  603,  595,  588,  581,  574,  567,  561,  554,  548,  542,
    535,  529,  523,  517,  512,  506,  500,  495,  489,  484,  478,  473,
    468,  463,  458,  453,  448,  443,  438,  434,  429,  424,  420,  415,
    411,  407,  402,  398,  394,  390,  386,  382,  377,  373,  370,  366,
    362,  358,  354,  350,  347,  343,  339,  336,  332,  329,  325,  322,
    318,  315,  311,  308,  305,  302,  298,  295,  292,  289,  286,  282,
    279,  276,  273,  270,  267,  264,  261,  258,  256,  253,  250,  247,
    244,  241,  239,  236,  233,  230,  228,  225,  222,  220,  217,  215,
    212,  209,  207,  204,  202,  199,  197,  194,  192,  190,  187,  185,
    182,  180,  178,  175,  173,  171,  168,  166,  164,  162,  159,  157,
    155,  153,  151,  149,  146,  144,  142,  140,  138,  136,  134,  132,
    130,  128,  126,  123,  121,  119,  117,  115,  114,  112,  110,  108,
    106,  104,  102,  100,  98,   96,   94,   93,   91,   89,   87,   85,
    83,   82,   80,   78,   76,   74,   73,   71,   69,   67,   66,   64,
    62,   61,   59,   57,   55,   54,   52,   50,   49,   47,   46,   44,
    42,   41,   39,   37,   36,   34,   33,   31,   30,   28,   26,   25,
    23,   22,   20,   19,   17,   16,   14,   13,   11,   10,   8,    7,
    5,    4,    2,    1,
];

/// `ZSTD_useLowProbCount`.
fn use_low_prob_count(nb_seq: usize) -> bool {
    nb_seq >= 2048
}

/// `ZSTD_NCountCost`: the byte cost of the serialized normalized counts.
fn ncount_cost(count: &[u32], max: u32, nb_seq: usize, fse_log: u32) -> Result<usize, Error> {
    let table_log = fse_encode::optimal_table_log(fse_log, nb_seq, max);
    match fse_encode::normalize_count(count, nb_seq, max, table_log, use_low_prob_count(nb_seq))? {
        Normalized::Table(norm) => Ok(fse_encode::write_ncount(&norm, max, table_log)?.len()),
        // Unreachable: callers exclude the single-symbol case before costing.
        Normalized::Rle(_) => Err(Error::Encode("RLE distribution in NCount cost")),
    }
}

/// `ZSTD_entropyCost`: entropy bound, in bits, of `count` under itself.
fn entropy_cost(count: &[u32], max: u32, total: usize) -> u64 {
    debug_assert!(total > 0);
    let mut cost = 0u64;
    for s in 0..=max as usize {
        if count[s] == 0 {
            continue;
        }
        let mut norm = (256 * count[s] as u64 / total as u64) as usize;
        if norm == 0 {
            norm = 1;
        }
        cost += count[s] as u64 * u64::from(K_INVERSE_PROBABILITY_LOG256[norm]);
    }
    cost >> 8
}

/// `ZSTD_crossEntropyCost`: bits to encode `count` under the distribution
/// described by `norm` (a table with `accuracy_log` accuracy).
fn cross_entropy_cost(norm: &[i16], accuracy_log: u32, count: &[u32], max: u32) -> u64 {
    let shift = 8 - accuracy_log;
    let mut cost = 0u64;
    for s in 0..=max as usize {
        let norm_acc = if norm[s] == -1 { 1u32 } else { norm[s] as u32 };
        let norm256 = (norm_acc << shift) as usize;
        debug_assert!(norm256 > 0 && norm256 < 256);
        cost += count[s] as u64 * u64::from(K_INVERSE_PROBABILITY_LOG256[norm256]);
    }
    cost >> 8
}

/// `ZSTD_fseBitCost`: bits to encode `count` with the previous block's table,
/// or `None` if that table cannot represent every needed symbol.
fn fse_bit_cost(ct: &FseCTable, count: &[u32], max: u32) -> Option<u64> {
    const K_ACCURACY_LOG: u32 = 8;
    if ct.max_symbol() < max {
        return None;
    }
    let table_log = ct.table_log();
    let bad_cost = (table_log + 1) << K_ACCURACY_LOG;
    let mut cost = 0u64;
    for s in 0..=max {
        let bit_cost = ct.bit_cost(s, K_ACCURACY_LOG);
        if count[s as usize] == 0 {
            continue;
        }
        if bit_cost >= bad_cost {
            return None; // symbol has probability 0 in the previous table
        }
        cost += count[s as usize] as u64 * u64::from(bit_cost);
    }
    Some(cost >> K_ACCURACY_LOG)
}

/// `ZSTD_selectEncodingType`, verbatim including both the cheap-heuristic
/// branch (strategy < lazy) and the cost-comparison branch.
#[allow(clippy::too_many_arguments)]
fn select_encoding_type(
    repeat_mode: &mut FseRepeat,
    count: &[u32],
    max: u32,
    most_frequent: usize,
    nb_seq: usize,
    fse_log: u32,
    prev_ctable: Option<&FseCTable>,
    default_norm: &[i16],
    default_norm_log: u32,
    is_default_allowed: bool,
    strategy: i32,
) -> Result<SymbolEncodingType, Error> {
    const ZSTD_LAZY: i32 = 4;
    if most_frequent == nb_seq {
        *repeat_mode = FseRepeat::None;
        if is_default_allowed && nb_seq <= 2 {
            // set_basic costs 5-6 bits/symbol vs RLE's whole byte for <= 2.
            return Ok(SymbolEncodingType::Basic);
        }
        return Ok(SymbolEncodingType::Rle);
    }
    if strategy < ZSTD_LAZY {
        if is_default_allowed {
            let static_fse_nb_seq_max = 1000usize;
            let mult = (10 - strategy) as usize;
            let base_log = 3usize;
            // 28-36 for offsets, 56-72 for lengths.
            let dynamic_fse_nb_seq_min = ((1usize << default_norm_log) * mult) >> base_log;
            if *repeat_mode == FseRepeat::Valid && nb_seq < static_fse_nb_seq_max {
                return Ok(SymbolEncodingType::Repeat);
            }
            if nb_seq < dynamic_fse_nb_seq_min || most_frequent < (nb_seq >> (default_norm_log - 1))
            {
                // Default tables are never flagged for repeat at low strategies.
                *repeat_mode = FseRepeat::None;
                return Ok(SymbolEncodingType::Basic);
            }
        }
    } else {
        let basic_cost = if is_default_allowed {
            cross_entropy_cost(default_norm, default_norm_log, count, max)
        } else {
            u64::MAX
        };
        let repeat_cost = if *repeat_mode != FseRepeat::None {
            prev_ctable
                .and_then(|ct| fse_bit_cost(ct, count, max))
                .unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        let ncount_cost_bytes = ncount_cost(count, max, nb_seq, fse_log)? as u64;
        let compressed_cost = (ncount_cost_bytes << 3) + entropy_cost(count, max, nb_seq);

        if basic_cost <= repeat_cost && basic_cost <= compressed_cost {
            debug_assert!(is_default_allowed);
            *repeat_mode = FseRepeat::None;
            return Ok(SymbolEncodingType::Basic);
        }
        if repeat_cost <= compressed_cost {
            return Ok(SymbolEncodingType::Repeat);
        }
    }
    *repeat_mode = FseRepeat::Check;
    Ok(SymbolEncodingType::Compressed)
}

// --- Table building -----------------------------------------------------------

/// `ZSTD_buildCTable` (sequences flavor): produce the table for `type` and the
/// header bytes (NCount description, RLE byte, or nothing) it adds to the
/// stream. `count` is mutated by the set_compressed last-sequence adjustment,
/// exactly as in C.
#[allow(clippy::too_many_arguments)]
fn build_seq_ctable(
    enc_type: SymbolEncodingType,
    fse_log: u32,
    count: &mut [u32],
    max: u32,
    code_table: &[u8],
    nb_seq: usize,
    default_norm: &[i16],
    default_norm_log: u32,
    default_max: u32,
    prev_ctable: Option<&FseCTable>,
) -> Result<(FseCTable, Vec<u8>), Error> {
    match enc_type {
        SymbolEncodingType::Rle => Ok((FseCTable::rle(max as u8), vec![code_table[0]])),
        SymbolEncodingType::Repeat => {
            let prev = prev_ctable.ok_or(Error::Encode("repeat mode without previous table"))?;
            Ok((prev.clone(), Vec::new()))
        }
        SymbolEncodingType::Basic => Ok((
            fse_encode::build_ctable(default_norm, default_max, default_norm_log),
            Vec::new(),
        )),
        SymbolEncodingType::Compressed => {
            let table_log = fse_encode::optimal_table_log(fse_log, nb_seq, max);
            let mut nb_seq_1 = nb_seq;
            // The last sequence's symbol is implicit in the final FSE state,
            // so its count is reduced before normalization when possible.
            let last = code_table[nb_seq - 1] as usize;
            if count[last] > 1 {
                count[last] -= 1;
                nb_seq_1 -= 1;
            }
            debug_assert!(nb_seq_1 > 1);
            match fse_encode::normalize_count(
                count,
                nb_seq_1,
                max,
                table_log,
                use_low_prob_count(nb_seq_1),
            )? {
                Normalized::Table(norm) => {
                    let header = fse_encode::write_ncount(&norm, max, table_log)?;
                    Ok((fse_encode::build_ctable(&norm, max, table_log), header))
                }
                Normalized::Rle(_) => Err(Error::Encode("degenerate compressed distribution")),
            }
        }
    }
}

// --- Sequence bitstream ---------------------------------------------------------

/// `ZSTD_encodeSequences` (64-bit body, `longOffsets` impossible — see module
/// docs). Encodes the sequences in reverse, interleaving the three FSE states
/// with the extra-bit fields, and closes the backward-readable stream.
fn encode_sequences(
    ml_ct: &FseCTable,
    ml_codes: &[u8],
    of_ct: &FseCTable,
    of_codes: &[u8],
    ll_ct: &FseCTable,
    ll_codes: &[u8],
    sequences: &[SeqDef],
) -> Vec<u8> {
    let nb_seq = sequences.len();
    debug_assert!(nb_seq > 0);
    let mut bitc = BitCStream::new();

    // First (last-read) symbols seed the states; their extra bits follow.
    let last = nb_seq - 1;
    let mut state_ml = fse_encode::init_cstate2(ml_ct, ml_codes[last] as usize);
    let mut state_of = fse_encode::init_cstate2(of_ct, of_codes[last] as usize);
    let mut state_ll = fse_encode::init_cstate2(ll_ct, ll_codes[last] as usize);
    bitc.add_bits(
        u64::from(sequences[last].lit_length),
        LL_BITS[ll_codes[last] as usize],
    );
    bitc.add_bits(
        u64::from(sequences[last].ml_base),
        ML_BITS[ml_codes[last] as usize],
    );
    bitc.add_bits(
        u64::from(sequences[last].off_base),
        u32::from(of_codes[last]),
    );
    bitc.flush_bits();

    for n in (0..nb_seq - 1).rev() {
        let ll_c = ll_codes[n] as usize;
        let of_c = of_codes[n] as usize;
        let ml_c = ml_codes[n] as usize;
        let ll_bits = LL_BITS[ll_c];
        let of_bits = of_c as u32;
        let ml_bits = ML_BITS[ml_c];

        fse_encode::encode_symbol(&mut bitc, of_ct, &mut state_of, of_c);
        fse_encode::encode_symbol(&mut bitc, ml_ct, &mut state_ml, ml_c);
        fse_encode::encode_symbol(&mut bitc, ll_ct, &mut state_ll, ll_c);
        // 64 - 7 - (LLFSELog + MLFSELog + OffFSELog) = 31.
        if of_bits + ml_bits + ll_bits >= 31 {
            bitc.flush_bits();
        }
        bitc.add_bits(u64::from(sequences[n].lit_length), ll_bits);
        bitc.add_bits(u64::from(sequences[n].ml_base), ml_bits);
        if of_bits + ml_bits + ll_bits > 56 {
            bitc.flush_bits();
        }
        bitc.add_bits(u64::from(sequences[n].off_base), of_bits);
        bitc.flush_bits();
    }

    fse_encode::flush_cstate(&mut bitc, ml_ct, state_ml);
    fse_encode::flush_cstate(&mut bitc, of_ct, state_of);
    fse_encode::flush_cstate(&mut bitc, ll_ct, state_ll);
    bitc.close()
}

// --- The entropy shell -----------------------------------------------------------

/// The compressor's cross-block entropy state (`ZSTD_entropyCTables_t`): the
/// literals Huffman table + repeat flag, and one FSE table + repeat flag per
/// sequence component.
///
/// `FseRepeat::Valid` arises only from dictionary loading (`ZSTD_loadCEntropy`);
/// a freshly built table leaves `Check`, which the cost-based selection branch
/// validates with `ZSTD_fseBitCost` before reuse. The Huffman side follows the
/// analogous `HUF_repeat` rules inside [`crate::literals_encode`].
#[derive(Clone, Default)]
pub(crate) struct FseEntropyState {
    pub huf: literals_encode::HufState,
    pub ll: Option<FseCTable>,
    pub ll_repeat: FseRepeat,
    pub of: Option<FseCTable>,
    pub of_repeat: FseRepeat,
    pub ml: Option<FseCTable>,
    pub ml_repeat: FseRepeat,
}

impl FseEntropyState {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

/// `SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO`.
const SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO: usize = 20;

/// `ZSTD_entropyCompressSeqStore`: build the complete `Compressed_Block` body
/// for `store` — literals section, sequence count, modes byte, table
/// descriptions, and the sequence bitstream. Returns the body and the
/// *candidate* next-block entropy state, or `None` when the block should be
/// emitted raw instead (incompressible, or one of the C fallback quirks).
///
/// The caller owns the commit decision, mirroring C's prev/next double
/// buffering: `ZSTD_blockState_confirmRepcodesAndEntropyTables` runs only when
/// the block is actually emitted compressed (`cSize > 1` — not for the
/// RLE-block override, not for raw fallbacks).
pub(crate) fn entropy_compress_seq_store(
    store: &SeqStore,
    entropy: &FseEntropyState,
    strategy: i32,
    disable_literal_compression: bool,
    block_size: usize,
) -> Result<Option<(Vec<u8>, FseEntropyState)>, Error> {
    let mut next = entropy.clone();
    let result = entropy_compress_seq_store_internal(
        store,
        &mut next,
        strategy,
        disable_literal_compression,
        block_size,
    )?;
    Ok(result.map(|body| (body, next)))
}

fn entropy_compress_seq_store_internal(
    store: &SeqStore,
    entropy: &mut FseEntropyState,
    strategy: i32,
    disable_literal_compression: bool,
    block_size: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let nb_seq = store.sequences.len();
    let lit_size = store.literals.len();

    // Literals section. Suspicion of uncompressibility is based on the
    // literals-to-sequences ratio. The Huffman state advances only when the
    // literals actually came out compressed or treeless.
    let suspect_uncompressible =
        nb_seq == 0 || lit_size / nb_seq >= SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO;
    let (mut out, next_huf) = literals_encode::compress_literals(
        &store.literals,
        strategy,
        suspect_uncompressible,
        disable_literal_compression,
        &entropy.huf,
    );
    if let Some(next_huf) = next_huf {
        entropy.huf = next_huf;
    }

    // Sequences header.
    if nb_seq < 128 {
        out.push(nb_seq as u8);
    } else if nb_seq < LONG_NB_SEQ {
        out.push(((nb_seq >> 8) + 0x80) as u8);
        out.push(nb_seq as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&((nb_seq - LONG_NB_SEQ) as u16).to_le_bytes());
    }
    if nb_seq == 0 {
        // Entropy tables carry over untouched, as if repeated.
        return finish_block(out, strategy, block_size);
    }

    let (ll_codes, of_codes, ml_codes) = seq_to_codes(store);

    // Per-component stats, encoding-type selection, and table building
    // (`ZSTD_buildSequencesStatistics`).
    let mut last_count_size = 0usize;
    let modes_at = out.len();
    out.push(0); // placeholder for the modes byte

    let build = |codes: &[u8],
                 format_max: u32,
                 fse_log: u32,
                 default_norm: &[i16],
                 default_norm_log: u32,
                 default_max: u32,
                 default_allowed_cap: Option<u32>,
                 prev: Option<&FseCTable>,
                 repeat: &mut FseRepeat|
     -> Result<(SymbolEncodingType, FseCTable, Vec<u8>), Error> {
        let mut count = vec![0u32; format_max as usize + 1];
        for &c in codes {
            count[c as usize] += 1;
        }
        let mut max = format_max;
        while max > 0 && count[max as usize] == 0 {
            max -= 1;
        }
        let most_frequent = *count.iter().max().unwrap() as usize;
        let is_default_allowed = default_allowed_cap.is_none_or(|cap| max <= cap);
        let enc_type = select_encoding_type(
            repeat,
            &count,
            max,
            most_frequent,
            nb_seq,
            fse_log,
            prev,
            default_norm,
            default_norm_log,
            is_default_allowed,
            strategy,
        )?;
        let (ctable, header) = build_seq_ctable(
            enc_type,
            fse_log,
            &mut count,
            max,
            codes,
            nb_seq,
            default_norm,
            default_norm_log,
            default_max,
            prev,
        )?;
        Ok((enc_type, ctable, header))
    };

    let (ll_type, ll_ct, ll_hdr) = build(
        &ll_codes,
        MAX_LL,
        LL_FSE_LOG,
        &LL_DEFAULT_NORM,
        LL_DEFAULT_LOG,
        MAX_LL,
        None,
        entropy.ll.as_ref(),
        &mut entropy.ll_repeat,
    )?;
    if ll_type == SymbolEncodingType::Compressed {
        last_count_size = ll_hdr.len();
    }
    out.extend_from_slice(&ll_hdr);

    let (of_type, of_ct, of_hdr) = build(
        &of_codes,
        MAX_OFF,
        OFF_FSE_LOG,
        &OF_DEFAULT_NORM,
        OF_DEFAULT_LOG,
        DEFAULT_MAX_OFF,
        Some(DEFAULT_MAX_OFF),
        entropy.of.as_ref(),
        &mut entropy.of_repeat,
    )?;
    if of_type == SymbolEncodingType::Compressed {
        last_count_size = of_hdr.len();
    }
    out.extend_from_slice(&of_hdr);

    let (ml_type, ml_ct, ml_hdr) = build(
        &ml_codes,
        MAX_ML,
        ML_FSE_LOG,
        &ML_DEFAULT_NORM,
        ML_DEFAULT_LOG,
        MAX_ML,
        None,
        entropy.ml.as_ref(),
        &mut entropy.ml_repeat,
    )?;
    if ml_type == SymbolEncodingType::Compressed {
        last_count_size = ml_hdr.len();
    }
    out.extend_from_slice(&ml_hdr);

    out[modes_at] = ((ll_type as u8) << 6) | ((of_type as u8) << 4) | ((ml_type as u8) << 2);

    // The sequence bitstream itself.
    let bitstream = encode_sequences(
        &ml_ct,
        &ml_codes,
        &of_ct,
        &of_codes,
        &ll_ct,
        &ll_codes,
        &store.sequences,
    );
    let bitstream_size = bitstream.len();
    out.extend_from_slice(&bitstream);

    // Workaround for a zstd <= 1.3.4 decoder bug: a trailing 2-byte
    // set_compressed NCount plus a 1-byte bitstream triggers a false
    // corruption error there, so C emits the block uncompressed instead.
    if last_count_size > 0 && last_count_size + bitstream_size < 4 {
        debug_assert_eq!(last_count_size + bitstream_size, 3);
        return Ok(None);
    }

    // The new tables become the candidate next-block state; the repeat flags
    // were already updated in place by the selection step (None for
    // basic/RLE, Check for freshly compressed, untouched for repeat).
    entropy.ll = Some(ll_ct);
    entropy.of = Some(of_ct);
    entropy.ml = Some(ml_ct);

    finish_block(out, strategy, block_size)
}

/// The trailing compressibility gate of `ZSTD_entropyCompressSeqStore`.
fn finish_block(out: Vec<u8>, strategy: i32, block_size: usize) -> Result<Option<Vec<u8>>, Error> {
    let max_c_size = block_size - literals_encode::min_gain(block_size, strategy);
    if out.len() >= max_c_size {
        return Ok(None); // block not compressible enough
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{self, BLOCK_SIZE_MAX, FrameContext};
    use std::collections::HashMap;

    /// Decode one emitted block body into `out` with the given frame context.
    fn decode_block(body: &[u8], ctx: &mut FrameContext, out: &mut Vec<u8>) {
        block::decode_compressed_block(ctx, body, out, 0, &[], BLOCK_SIZE_MAX, usize::MAX)
            .unwrap_or_else(|e| panic!("decoding our emitted block failed: {e}"));
    }

    /// Compress a store and require a compressed (non-fallback) block.
    fn compress(store: &SeqStore, strategy: i32, block_size: usize) -> Vec<u8> {
        let entropy = FseEntropyState::new();
        entropy_compress_seq_store(store, &entropy, strategy, false, block_size)
            .unwrap()
            .expect("expected a compressible block")
            .0
    }

    /// Like [`compress`], but without the block-level compressibility gate —
    /// for tiny handcrafted blocks that a real compressor would emit raw.
    fn compress_ungated(store: &SeqStore, strategy: i32, block_size: usize) -> Vec<u8> {
        let mut entropy = FseEntropyState::new();
        entropy_compress_seq_store_internal(store, &mut entropy, strategy, false, usize::MAX)
            .unwrap()
            .unwrap_or_else(|| panic!("ungated compression returned None ({block_size} bytes)"))
    }

    /// A naive greedy matcher: 4-byte hash chaining, emitting real offsets
    /// only. Not a zstd match finder — just a generator of valid seqStores.
    fn greedy_store(data: &[u8]) -> SeqStore {
        let mut store = SeqStore::new();
        let mut map: HashMap<[u8; 4], usize> = HashMap::new();
        let mut anchor = 0usize;
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let key: [u8; 4] = data[i..i + 4].try_into().unwrap();
            if let Some(&prev) = map.get(&key) {
                if data[prev..prev + 4] == data[i..i + 4] {
                    let mut len = 4usize;
                    while i + len < data.len() && data[prev + len] == data[i + len] {
                        len += 1;
                    }
                    store.store_seq(&data[anchor..i], (i - prev + 3) as u32, len as u32);
                    i += len;
                    anchor = i;
                    continue;
                }
            }
            map.insert(key, i);
            i += 1;
        }
        store.store_last_literals(&data[anchor..]);
        store
    }

    fn word_salad(seed: u64, len: usize) -> Vec<u8> {
        const WORDS: &[&[u8]] = &[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf", b"hotel",
            b"india", b"juliet",
        ];
        let mut s = seed | 1;
        let mut data = Vec::with_capacity(len + 8);
        while data.len() < len {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            let r = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
            data.extend_from_slice(WORDS[(r % WORDS.len() as u64) as usize]);
            data.push(b' ');
        }
        data.truncate(len);
        data
    }

    #[test]
    fn handcrafted_real_and_repeat_offsets() {
        // "abcabcabc" via offset 3, then "xyzxyz" via repeat-offset 1.
        let data = b"abcabcabcxyzxyz";
        let mut store = SeqStore::new();
        store.store_seq(b"abc", 3 + 3, 6); // real offset 3
        store.store_seq(b"xyz", 1, 3); // repcode 1 (most recent offset, 3)
        let body = compress_ungated(&store, 1, data.len());
        let mut out = Vec::new();
        decode_block(&body, &mut FrameContext::new(), &mut out);
        assert_eq!(out, data);
    }

    #[test]
    fn single_sequence_block() {
        let data = b"0123456789_0123456789";
        let mut store = SeqStore::new();
        store.store_seq(b"0123456789_", 11 + 3, 10);
        let body = compress_ungated(&store, 3, data.len());
        let mut out = Vec::new();
        decode_block(&body, &mut FrameContext::new(), &mut out);
        assert_eq!(out, data);
    }

    /// All-identical sequences drive every component to the RLE table mode,
    /// across all three forms of the sequence-count header.
    #[test]
    fn rle_tables_and_nbseq_header_forms() {
        // 32_700 crosses the LONG_NB_SEQ (0x7F00) threshold while keeping the
        // block within ZSTD_BLOCKSIZE_MAX.
        for &nb_seq in &[5usize, 200, 32_700] {
            let data = vec![b'a'; 4 * nb_seq];
            let mut store = SeqStore::new();
            let mut pos = 0usize;
            for _ in 0..nb_seq {
                store.store_seq(&data[pos..pos + 1], 1 + 3, 3); // 'a' + 3-byte match, offset 1
                pos += 4;
            }
            assert!(data.len() <= BLOCK_SIZE_MAX);
            let body = compress(&store, 3, data.len());
            let mut out = Vec::new();
            decode_block(&body, &mut FrameContext::new(), &mut out);
            assert_eq!(out, data, "nbSeq={nb_seq}");
        }
    }

    /// Compressed FSE tables (heuristic branch at strategy 1, cost branch at
    /// strategy 6) over a realistic seqStore from the naive matcher.
    #[test]
    fn matcher_blocks_round_trip_across_strategies() {
        for &len in &[2_000usize, 40_000, 120_000] {
            let data = word_salad(0x5E0D ^ len as u64, len);
            let store = greedy_store(&data);
            assert!(!store.sequences.is_empty(), "matcher found no matches");
            for strategy in [1, 3, 6, 9] {
                let entropy = FseEntropyState::new();
                let (body, _next) =
                    entropy_compress_seq_store(&store, &entropy, strategy, false, data.len())
                        .unwrap()
                        .expect("word salad must compress");
                let mut out = Vec::new();
                decode_block(&body, &mut FrameContext::new(), &mut out);
                assert_eq!(out, data, "len={len} strategy={strategy}");
            }
        }
    }

    /// Two consecutive blocks with identical statistics: the second must be
    /// decodable against the carried-over decoder context, and with
    /// `FSE_repeat_valid` tables at a low strategy the heuristic branch
    /// deterministically picks Repeat_Mode. (Valid is only sound when the
    /// tables cover every symbol the next block uses — guaranteed here by
    /// compressing the same seqStore twice; in C, only dictionary loading
    /// makes that promise.)
    #[test]
    fn repeat_mode_across_blocks() {
        let data = word_salad(0xAAAA, 6_000);
        let store1 = greedy_store(&data);
        let store2 = greedy_store(&data);
        assert!(store2.sequences.len() < 1000, "below the repeat-gate limit");

        let entropy = FseEntropyState::new();
        let (body1, mut entropy) =
            entropy_compress_seq_store(&store1, &entropy, 6, false, data.len())
                .unwrap()
                .unwrap();
        // Promote the freshly built tables to Valid, as ZSTD_loadCEntropy
        // would for a dictionary, so the strategy-1 heuristic reuses them.
        entropy.ll_repeat = FseRepeat::Valid;
        entropy.of_repeat = FseRepeat::Valid;
        entropy.ml_repeat = FseRepeat::Valid;
        let (body2, _next) = entropy_compress_seq_store(&store2, &entropy, 1, false, data.len())
            .unwrap()
            .unwrap();

        // Locate block 2's modes byte: after the literals section and the
        // sequence-count header.
        let mut probe_ctx = FrameContext::new();
        let (_, lit_len) = block::decode_literals(&mut probe_ctx, &body2, BLOCK_SIZE_MAX).unwrap();
        let nb_seq_header = match body2[lit_len] {
            b if b < 128 => 1,
            0xFF => 3,
            _ => 2,
        };
        let modes = body2[lit_len + nb_seq_header];
        let types = [(modes >> 6) & 3, (modes >> 4) & 3, (modes >> 2) & 3];
        assert!(
            types.contains(&(SymbolEncodingType::Repeat as u8)),
            "expected at least one Repeat_Mode component in block 2, got {types:?}"
        );

        // Both blocks decode against one shared context, like a real frame.
        let mut ctx = FrameContext::new();
        let mut out = Vec::new();
        decode_block(&body1, &mut ctx, &mut out);
        decode_block(&body2, &mut ctx, &mut out);
        let expected: Vec<u8> = data.iter().chain(data.iter()).copied().collect();
        assert_eq!(out, expected);
    }

    /// A literal run beyond 65535 bytes exercises the long-length marker.
    #[test]
    fn long_literal_length_marker() {
        let lits = word_salad(0x10_06, 70_000);
        let mut data = lits.clone();
        data.extend_from_slice(&lits[..8]);
        let mut store = SeqStore::new();
        store.store_seq(&lits, 70_000 + 3, 8);
        assert_eq!(store.long_length_type, LongLengthType::LiteralLength);
        let body = compress(&store, 3, data.len());
        let mut out = Vec::new();
        decode_block(&body, &mut FrameContext::new(), &mut out);
        assert_eq!(out, data);
    }

    /// No sequences at all: the body is a literals section plus a zero count.
    #[test]
    fn literals_only_block() {
        let lits = word_salad(0x1177, 5_000);
        let mut store = SeqStore::new();
        store.store_last_literals(&lits);
        let body = compress(&store, 3, lits.len());
        let mut out = Vec::new();
        decode_block(&body, &mut FrameContext::new(), &mut out);
        assert_eq!(out, lits);
    }

    /// Incompressible input falls back to a raw block (None).
    #[test]
    fn incompressible_returns_none() {
        let mut s = 0x9E37_79B9u64;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8
            })
            .collect();
        let mut store = SeqStore::new();
        store.store_last_literals(&data);
        let entropy = FseEntropyState::new();
        let r = entropy_compress_seq_store(&store, &entropy, 3, false, data.len()).unwrap();
        assert!(
            r.is_none(),
            "random bytes must not produce a compressed block"
        );
    }
}
