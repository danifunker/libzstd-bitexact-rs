//! Long-distance matching (`zstd_ldm.c`): a rolling gear hash splits the
//! input into content-defined fragments, each fragment's trailing
//! `minMatchLength` bytes are XXH64-fingerprinted into a bucketed hash table,
//! and matches against earlier fingerprints become *raw sequences*
//! (literal-run / match-length / offset triples) over the LDM window.
//!
//! Through the level-based API, C auto-enables LDM only for `strategy >=
//! btopt && windowLog >= 27` (`ZSTD_resolveEnableLdm`), so the only
//! reachable consumer is the optimal parser, which takes the raw sequences
//! as extra match *candidates* (`ZSTD_ldm_blockCompress`'s `strategy >=
//! ZSTD_btopt` branch; that candidate plumbing lives in [`crate::opt`]). The
//! non-opt path — chopping blocks at LDM sequences and running the block
//! compressor on the literal stretches — is unreachable without an LDM
//! parameter API and is not ported.
//!
//! **Status: bit-exact.** The raw sequences are byte-identical to
//! `ZSTD_ldm_generateSequences`, verified against the C oracle at level 22
//! (unknown-size streaming and one-shot above 64 MiB). The one subtlety that
//! had to be matched bug-for-bug is in [`GearHash::reset`]: zstd 1.5.7's
//! `ZSTD_ldm_gear_reset` is a no-op (it computes a fresh rolling hash but is
//! missing the `state->rolling = hash;` writeback), so the gear hash is never
//! re-seeded — every block's split scan begins from the
//! `ZSTD_ldm_gear_init` constant. Re-seeding it (the "obvious" port) silently
//! shifts each block's first `minMatchLength` splits and manufactures extra
//! raw matches once the hash table is populated.

use crate::compress::{CParams, Strategy, Window, count_2segments, count_eq};
use crate::error::Error;
use crate::xxhash::xxh64;

// zstd 1.5.5 defaults. 1.5.6 retuned LDM_BUCKET_SIZE_LOG to 4 and made the
// effective bucket/rate/minMatch strategy-derived (see `LdmParams::auto`).
const LDM_BUCKET_SIZE_LOG: u32 = 3;
const LDM_MIN_MATCH_LENGTH: u32 = 64;
/// `LDM_HASH_RLOG`: the fixed window-to-hash log reduction 1.5.5 uses to size
/// the LDM hash table (1.5.6 replaced it with the strategy-derived hashRateLog).
const LDM_HASH_RLOG: u32 = 7;
const LDM_BATCH_SIZE: usize = 64;
const HASH_READ_SIZE: usize = 8;
const ZSTD_HASHLOG_MIN: u32 = 6;
const ZSTD_HASHLOG_MAX: u32 = 30;
const ZSTD_LDM_BUCKETSIZELOG_MAX: u32 = 8;
/// `kMaxChunkSize` in `ZSTD_ldm_generateSequences`.
const K_MAX_CHUNK_SIZE: usize = 1 << 20;

/// `ZSTD_ldm_gearTab` (zstd_ldm_geartab.h), extracted verbatim.
#[rustfmt::skip]
static GEAR_TAB: [u64; 256] = [
    0xf5b8f72c5f77775c, 0x84935f266b7ac412, 0xb647ada9ca730ccc, 0xb065bb4b114fb1de,
    0x34584e7e8c3a9fd0, 0x4e97e17c6ae26b05, 0x3a03d743bc99a604, 0xcecd042422c4044f,
    0x76de76c58524259e, 0x9c8528f65badeaca, 0x86563706e2097529, 0x2902475fa375d889,
    0xafb32a9739a5ebe6, 0xce2714da3883e639, 0x021eaf821722e69e, 0x00037b628620b628,
    0x049a8d455d88caf5, 0x8556d711e6958140, 0x04f7ae74fc605c1f, 0x829f0c3468bd3a20,
    0x4ffdc885c625179e, 0x8473de048a3daf1b, 0x51008822b05646b2, 0x69d75d12b2d1cc5f,
    0x8c9d4a19159154bc, 0xc3cc10f4abbd4003, 0xd06ddc1cecb97391, 0xbe48e6e7ed80302e,
    0x3481db31cee03547, 0xacc3f67cdaa1d210, 0x65cb771d8c7f96cc, 0x8eb27177055723dd,
    0xc789950d44cd94be, 0x934feadc3700b12b, 0x5e485f11edbdf182, 0x1e2e2a46fd64767a,
    0x2969ca71d82efa7c, 0x9d46e9935ebbba2e, 0xe056b67e05e6822b, 0x94d73f55739d03a0,
    0xcd7010bdb69b5a03, 0x455ef9fcd79b82f4, 0x869cb54a8749c161, 0x38d1a4fa6185d225,
    0xb475166f94bbe9bb, 0xa4143548720959f1, 0x7aed4780ba6b26ba, 0xd0ce264439e02312,
    0x84366d746078d508, 0xa8ce973c72ed17be, 0x21c323a29a430b01, 0x9962d617e3af80ee,
    0xab0ce91d9c8cf75b, 0x530e8ee6d19a4dbc, 0x2ef68c0cf53f5d72, 0xc03a681640a85506,
    0x496e4e9f9c310967, 0x78580472b59b14a0, 0x273824c23b388577, 0x66bf923ad45cb553,
    0x47ae1a5a2492ba86, 0x35e304569e229659, 0x4765182a46870b6f, 0x6cbab625e9099412,
    0xddac9a2e598522c1, 0x7172086e666624f2, 0xdf5003ca503b7837, 0x88c0c1db78563d09,
    0x58d51865acfc289d, 0x177671aec65224f1, 0xfb79d8a241e967d7, 0x2be1e101cad9a49a,
    0x6625682f6e29186b, 0x399553457ac06e50, 0x035dffb4c23abb74, 0x429db2591f54aade,
    0xc52802a8037d1009, 0x6acb27381f0b25f3, 0xf45e2551ee4f823b, 0x8b0ea2d99580c2f7,
    0x3bed519cbcb4e1e1, 0x0ff452823dbb010a, 0x9d42ed614f3dd267, 0x5b9313c06257c57b,
    0xa114b8008b5e1442, 0xc1fe311c11c13d4b, 0x66e8763ea34c5568, 0x8b982af1c262f05d,
    0xee8876faaa75fbb7, 0x8a62a4d0d172bb2a, 0xc13d94a3b7449a97, 0x6dbbba9dc15d037c,
    0xc786101f1d92e0f1, 0xd78681a907a0b79b, 0xf61aaf2962c9abb9, 0x2cfd16fcd3cb7ad9,
    0x868c5b6744624d21, 0x25e650899c74ddd7, 0xba042af4a7c37463, 0x4eb1a539465a3eca,
    0xbe09dbf03b05d5ca, 0x774e5a362b5472ba, 0x47a1221229d183cd, 0x504b0ca18ef5a2df,
    0xdffbdfbde2456eb9, 0x46cd2b2fbee34634, 0xf2aef8fe819d98c3, 0x357f5276d4599d61,
    0x24a5483879c453e3, 0x088026889192b4b9, 0x28da96671782dbec, 0x4ef37c40588e9aaa,
    0x8837b90651bc9fb3, 0xc164f741d3f0e5d6, 0xbc135a0a704b70ba, 0x069cd868f7622ada,
    0xbc37ba89e0b9c0ab, 0x47c14a01323552f6, 0x4f00794bacee98bb, 0x7107de7d637a69d5,
    0x88af793bb6f2255e, 0xf3c6466b8799b598, 0xc288c616aa7f3b59, 0x81ca63cf42fca3fd,
    0x88d85ace36a2674b, 0x0d056bd3792389e7, 0xe55c396c4e9dd32d, 0xbefb504571e6c0a6,
    0x96ab32115e91e8cc, 0xbf8acb18de8f38d1, 0x66dae58801672606, 0x833b6017872317fb,
    0xb87c16f2d1c92864, 0xdb766a74e58b669c, 0x89659f85c61417be, 0xc8daad856011ea0c,
    0x76a4b565b6fe7eae, 0xa469d085f6237312, 0xaaf0365683a3e96c, 0x4dbb746f8424f7b8,
    0x0638755af4e4acc1, 0x3d7807f5bde64486, 0x17be6d8f5bbb7639, 0x0903f0cd44dc35dc,
    0x67b672eafdf1196c, 0xa676ff93ed4c82f1, 0x521d1004c5053d9d, 0x37ba9ad09ccc9202,
    0x84e54d297aacfb51, 0x0a0b4b776a143445, 0x0820d471e20b348e, 0x1874383cb83d46dc,
    0x97edeec7a1efe11c, 0xb330e50b1bdc42aa, 0x1dd91955ce70e032, 0xa514cdb88f2939d5,
    0x2791233fd90db9d3, 0x7b670a4cc50f7a9b, 0x77c07d2a05c6dfa5, 0xe3778b6646d0a6fa,
    0xb39c8eda47b56749, 0x933ed448addbef28, 0xaf846af6ab7d0bf4, 0x0e5af208eb666e49,
    0x5e6622f73534cd6a, 0x297daeca42ef5b6e, 0x862daef3d35539a6, 0xe68722498f8e1ea9,
    0x981c53093dc0d572, 0xfa09b0bfbf86fbf5, 0x30b1e96166219f15, 0x70e7d466bdc4fb83,
    0x5a66736e35f2a8e9, 0xcddb59d2b7c1baef, 0xd6c7d247d26d8996, 0xea4e39eac8de1ba3,
    0x539c8bb19fa3aff2, 0x09f90e4c5fd508d8, 0xa34e5956fbaf3385, 0x2e2f8e151d3ef375,
    0x173691e9b83faec1, 0xb85a8d56bf016379, 0x8382381267408ae3, 0xb90f901bbdc0096d,
    0x7c6ad32933bcec65, 0x76bb5e2f2c8ad595, 0x390f851a6cf46d28, 0xc3e6064da1c2da72,
    0xc52a0c101cfa5389, 0xd78eaf84a3fbc530, 0x3781b9e2288b997e, 0x73c2f6dea83d05c4,
    0x04228e364c5b5ed7, 0x9d7a3edf0da43911, 0x8edcfeda24686756, 0x5e7667a7b7a9b3a1,
    0x4c4f389fa143791d, 0xb08bc1023da7cddc, 0x7ab4be3ae529b1cc, 0x754e6132dbe74ff9,
    0x71635442a839df45, 0x2f6fb1643fbe52de, 0x961e0a42cf7a8177, 0xf3b45d83d89ef2ea,
    0xee3de4cf4a6e3e9b, 0xcd6848542c3295e7, 0xe4cee1664c78662f, 0x9947548b474c68c4,
    0x25d73777a5ed8b0b, 0x00c915b1d636b7fc, 0x21c2ba75d9b0d2da, 0x5f6b5dcf608a64a1,
    0xdcf333255ff9570c, 0x633b922418ced4ee, 0xc136dde0b004b34a, 0x58cc83b05d4b2f5a,
    0x5eb424dda28e42d2, 0x62df47369739cd98, 0xb4e0b42485e4ce17, 0x16e1f0c1f9a8d1e7,
    0x8ec3916707560ebf, 0x62ba6e2df2cc9db3, 0xcbf9f4ff77d83a16, 0x78d9d7d07d2bbcc4,
    0xef554ce1e02c41f4, 0x8d7581127eccf94d, 0xa9b53336cb3c8a05, 0x38c42c0bf45c4f91,
    0x640893cdf4488863, 0x80ec34bc575ea568, 0x39f324f5b48eaa40, 0xe9d9ed1f8eff527f,
    0x9224fc058cc5a214, 0xbaba00b04cfe7741, 0x309a9f120fcf52af, 0xa558f3ec65626212,
    0x424bec8b7adabe2f, 0x41622513a6aea433, 0xb88da2d5324ca798, 0xd287733b245528a4,
    0x9a44697e6d68aec3, 0x7b1093be2f49bb28, 0x50bbec632e3d8aad, 0x6cd90723e1ea8283,
    0x897b9e7431b02bf3, 0x219efdcb338a7047, 0x3b0311f0a27c0656, 0xdb17bf91c0db96e7,
    0x8cd4fd6b4e85a5b2, 0xfab071054ba6409d, 0x40d6fe831fa9dfd9, 0xaf358debad7d791e,
    0xeb8d0e25a65e3e58, 0xbbcbd3df14e08580, 0x0cf751f27ecdab2b, 0x2b4da14f2613d8f4,
];

/// `ldmParams_t` as resolved by `ZSTD_ldm_adjustParameters` from all-default
/// (zero) advanced parameters — the only configuration reachable through the
/// level-based API.
#[derive(Clone, Copy)]
pub(crate) struct LdmParams {
    pub(crate) hash_log: u32,
    pub(crate) bucket_size_log: u32,
    pub(crate) min_match_length: u32,
    hash_rate_log: u32,
    window_log: u32,
}

impl LdmParams {
    /// `ZSTD_resolveEnableLdm` (`ZSTD_ps_auto`) + `ZSTD_ldm_adjustParameters`
    /// with all-zero requested values.
    pub(crate) fn auto(cparams: &CParams) -> Option<LdmParams> {
        if !(cparams.strategy >= Strategy::Btopt && cparams.window_log >= 27) {
            return None;
        }
        let window_log = cparams.window_log;
        // `ZSTD_ldm_adjustParameters` (1.5.5) with all-zero requested params.
        // 1.5.6 retuned every default to be strategy-derived (hashRateLog =
        // 7 - strategy/3, minMatch halved at btultra+, bucketSizeLog from the
        // strategy); 1.5.5 uses fixed constants:
        //   hashLog     = MAX(HASHLOG_MIN, windowLog - LDM_HASH_RLOG)
        //   hashRateLog = windowLog < hashLog ? 0 : windowLog - hashLog
        //   minMatch    = LDM_MIN_MATCH_LENGTH        (never halved)
        //   bucketSize  = MIN(LDM_BUCKET_SIZE_LOG, hashLog)
        const _: () = assert!(LDM_BUCKET_SIZE_LOG <= ZSTD_LDM_BUCKETSIZELOG_MAX);
        let hash_log = (window_log - LDM_HASH_RLOG).max(ZSTD_HASHLOG_MIN);
        debug_assert!(hash_log <= ZSTD_HASHLOG_MAX);
        // C: `windowLog < hashLog ? 0 : windowLog - hashLog`.
        let hash_rate_log = window_log.saturating_sub(hash_log);
        let min_match_length = LDM_MIN_MATCH_LENGTH;
        let bucket_size_log = LDM_BUCKET_SIZE_LOG.min(hash_log);
        Some(LdmParams {
            hash_log,
            bucket_size_log,
            min_match_length,
            hash_rate_log,
            window_log,
        })
    }
}

/// `rawSeq`: `litLength` literals followed by a `matchLength` match at
/// `offset` (a raw distance — index-space-free, so the btultra2 initStats
/// window slide does not disturb it).
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawSeq {
    pub(crate) lit_length: u32,
    pub(crate) match_length: u32,
    pub(crate) offset: u32,
}

/// `ldmEntry_t`.
#[derive(Clone, Copy, Default)]
struct LdmEntry {
    offset: u32,
    checksum: u32,
}

/// `ldmState_t`: the bucketed fingerprint table plus the LDM's own window,
/// which mirrors every chunk registered with the main window.
pub(crate) struct LdmState {
    pub(crate) params: LdmParams,
    hash_table: Vec<LdmEntry>,
    /// `bucketOffsets`: next circular insertion slot per bucket.
    bucket_offsets: Vec<u8>,
    pub(crate) window: Window,
}

impl LdmState {
    pub(crate) fn new(params: LdmParams) -> Self {
        let h_size = 1usize << params.hash_log;
        let bucket_count = 1usize << (params.hash_log - params.bucket_size_log);
        LdmState {
            params,
            hash_table: vec![LdmEntry::default(); h_size],
            bucket_offsets: vec![0u8; bucket_count],
            window: Window::new(),
        }
    }

    /// `ZSTD_ldm_insertEntry`.
    fn insert_entry(&mut self, hash: u32, entry: LdmEntry) {
        let p_offset = &mut self.bucket_offsets[hash as usize];
        let offset = *p_offset as usize;
        self.hash_table[((hash as usize) << self.params.bucket_size_log) + offset] = entry;
        *p_offset = ((offset + 1) & ((1usize << self.params.bucket_size_log) - 1)) as u8;
    }
}

/// `ldmRollingHashState_t` + `ZSTD_ldm_gear_init`.
struct GearHash {
    rolling: u64,
    stop_mask: u64,
}

impl GearHash {
    fn new(params: &LdmParams) -> Self {
        let max_bits_in_mask = params.min_match_length.min(64);
        let hash_rate_log = params.hash_rate_log;
        let stop_mask = if hash_rate_log > 0 && hash_rate_log <= max_bits_in_mask {
            ((1u64 << hash_rate_log) - 1) << (max_bits_in_mask - hash_rate_log)
        } else {
            (1u64 << hash_rate_log) - 1
        };
        GearHash {
            rolling: !0u32 as u64,
            stop_mask,
        }
    }

    /// `ZSTD_ldm_gear_reset` — **a no-op in zstd 1.5.7, reproduced bug-for-bug.**
    ///
    /// The C function reads `state->rolling` into a local, feeds
    /// `minMatchLength` bytes into that local, then returns *without ever
    /// writing the result back* — it is missing the `state->rolling = hash;`
    /// store. So despite its name it never re-seeds the gear hash. Two
    /// consequences must be matched exactly for bit-exactness:
    ///
    /// 1. Each block's `feed` starts from the `ZSTD_ldm_gear_init` value
    ///    (`0xFFFFFFFF`), *not* from a hash of the block's first
    ///    `minMatchLength` bytes. The high (`stopMask`) bits of the seed only
    ///    influence the first `minMatchLength` split decisions of the block
    ///    before being shifted out, so a wrong seed silently shifts those
    ///    early splits — harmless on the first block (empty table) but, once
    ///    the table is populated, it manufactures extra raw matches that
    ///    perturb the optimal parse megabytes later.
    /// 2. The overlap-skip "reset" likewise does nothing: the rolling hash
    ///    simply continues across the skipped region.
    ///
    /// Verified against the C oracle (`ZSTD_ldm_generateSequences`): with the
    /// writeback present our raw sequences diverged at the second block; as a
    /// no-op they are byte-identical. The call sites are kept for traceability.
    fn reset(&mut self, _data: &[u8], _at: usize, _min_match_length: usize) {}

    /// `ZSTD_ldm_gear_feed`: record up to [`LDM_BATCH_SIZE`] split points in
    /// `data[at..at + size]`; returns the number of bytes processed.
    fn feed(
        &mut self,
        data: &[u8],
        at: usize,
        size: usize,
        splits: &mut [usize; LDM_BATCH_SIZE],
        num_splits: &mut usize,
    ) -> usize {
        let mut hash = self.rolling;
        let mask = self.stop_mask;
        let mut n = 0usize;
        while n < size {
            hash = (hash << 1).wrapping_add(GEAR_TAB[data[at + n] as usize]);
            n += 1;
            if hash & mask == 0 {
                splits[*num_splits] = n;
                *num_splits += 1;
                if *num_splits == LDM_BATCH_SIZE {
                    break;
                }
            }
        }
        self.rolling = hash;
        n
    }
}

/// `ZSTD_ldm_countBackwardsMatch`: bytes matching backwards before
/// `in_pos`/`match_pos`, bounded by `anchor_pos`/`match_base_pos`.
fn count_backwards_match(
    data: &[u8],
    mut in_pos: usize,
    anchor_pos: usize,
    mut match_pos: usize,
    match_base_pos: usize,
) -> usize {
    let mut match_length = 0usize;
    while in_pos > anchor_pos
        && match_pos > match_base_pos
        && data[in_pos - 1] == data[match_pos - 1]
    {
        in_pos -= 1;
        match_pos -= 1;
        match_length += 1;
    }
    match_length
}

/// `ZSTD_ldm_countBackwardsMatch_2segments`: continue a backwards count that
/// hit the prefix start into the extDict segment.
#[allow(clippy::too_many_arguments)]
fn count_backwards_match_2segments(
    data: &[u8],
    in_pos: usize,
    anchor_pos: usize,
    match_pos: usize,
    match_base_pos: usize,
    ext_dict_start_pos: usize,
    ext_dict_end_pos: usize,
) -> usize {
    let mut match_length =
        count_backwards_match(data, in_pos, anchor_pos, match_pos, match_base_pos);
    if match_pos - match_length != match_base_pos || match_base_pos == ext_dict_start_pos {
        // Backwards match entirely within the extDict or the prefix.
        return match_length;
    }
    match_length += count_backwards_match(
        data,
        in_pos - match_length,
        anchor_pos,
        ext_dict_end_pos,
        ext_dict_start_pos,
    );
    match_length
}

/// `ZSTD_ldm_generateSequences_internal`: generate raw sequences for one
/// chunk. `chunk_start..chunk_end` are positions in `data` (the history
/// buffer); sequence lit/match lengths are relative to `chunk_start`.
/// Returns the number of trailing un-sequenced bytes (`iend - anchor`).
fn generate_sequences_internal(
    state: &mut LdmState,
    seqs: &mut Vec<RawSeq>,
    capacity: usize,
    data: &[u8],
    chunk_start: usize,
    chunk_end: usize,
) -> Result<usize, Error> {
    let params = state.params;
    let ext_dict = state.window.has_ext_dict();
    let min_match_length = params.min_match_length as usize;
    let ents_per_bucket = 1usize << params.bucket_size_log;
    let h_bits = params.hash_log - params.bucket_size_log;
    // Prefix and extDict parameters (window indices; positions derived via
    // the segment biases).
    let seg_bias = state.window.seg_bias as usize;
    let dict_bias = state.window.dict_bias as usize;
    let dict_limit = state.window.dict_limit as usize;
    let lowest_index = if ext_dict {
        state.window.low_limit as usize
    } else {
        dict_limit
    };
    let dict_start_pos = lowest_index.wrapping_sub(dict_bias); // extDict only
    let dict_end_pos = dict_limit.wrapping_sub(dict_bias); // extDict only
    // `seg_bias` wraps (C's `base = ip - distanceFromBase` pointing before the
    // buffer) when the LDM window is updated over a `dict ++ src` staging buffer
    // whose input starts at `WINDOW_START_INDEX` — so this position conversion
    // must wrap too, exactly like the two siblings above.
    let low_prefix_pos = dict_limit.wrapping_sub(seg_bias);
    // Input bounds.
    let istart = chunk_start;
    let iend = chunk_end;
    let src_size = iend - istart;
    let mut anchor = istart;

    if src_size < min_match_length {
        return Ok(iend - anchor);
    }
    let ilimit = iend - HASH_READ_SIZE;

    let mut hash_state = GearHash::new(&params);
    hash_state.reset(data, istart, min_match_length);
    let mut ip = istart + min_match_length;

    let mut splits = [0usize; LDM_BATCH_SIZE];
    struct Candidate {
        split: usize,
        hash: u32,
        checksum: u32,
    }
    let mut candidates: Vec<Candidate> = Vec::with_capacity(LDM_BATCH_SIZE);

    while ip < ilimit {
        let mut num_splits = 0usize;
        let hashed = hash_state.feed(data, ip, ilimit - ip, &mut splits, &mut num_splits);

        candidates.clear();
        for &split_off in &splits[..num_splits] {
            let split = ip + split_off - min_match_length;
            let xxhash = xxh64(&data[split..split + min_match_length], 0);
            candidates.push(Candidate {
                split,
                hash: (xxhash & ((1u64 << h_bits) - 1)) as u32,
                checksum: (xxhash >> 32) as u32,
            });
        }

        for cand in &candidates {
            let split = cand.split;
            let checksum = cand.checksum;
            let hash = cand.hash;
            let new_entry = LdmEntry {
                offset: (split + seg_bias) as u32,
                checksum,
            };

            // A split that would generate a sequence overlapping the
            // previous one is merely registered in the hash table.
            if split < anchor {
                state.insert_entry(hash, new_entry);
                continue;
            }

            let mut forward_match_length = 0usize;
            let mut backward_match_length = 0usize;
            let mut best_match_length = 0usize;
            let mut best_entry: Option<LdmEntry> = None;

            let bucket_base = (hash as usize) << params.bucket_size_log;
            for slot in 0..ents_per_bucket {
                let cur = state.hash_table[bucket_base + slot];
                if cur.checksum != checksum || cur.offset as usize <= lowest_index {
                    continue;
                }
                let cur_forward;
                let cur_backward;
                if ext_dict {
                    let in_dict = (cur.offset as usize) < dict_limit;
                    let match_pos = if in_dict {
                        cur.offset as usize - dict_bias
                    } else {
                        cur.offset as usize - seg_bias
                    };
                    let match_end_pos = if in_dict { dict_end_pos } else { iend };
                    let low_match_pos = if in_dict {
                        dict_start_pos
                    } else {
                        low_prefix_pos
                    };
                    cur_forward = count_2segments(
                        data,
                        split,
                        match_pos,
                        iend,
                        match_end_pos,
                        low_prefix_pos,
                    );
                    if cur_forward < min_match_length {
                        continue;
                    }
                    cur_backward = count_backwards_match_2segments(
                        data,
                        split,
                        anchor,
                        match_pos,
                        low_match_pos,
                        dict_start_pos,
                        dict_end_pos,
                    );
                } else {
                    let match_pos = cur.offset as usize - seg_bias;
                    cur_forward = count_eq(data, split, match_pos, iend);
                    if cur_forward < min_match_length {
                        continue;
                    }
                    cur_backward =
                        count_backwards_match(data, split, anchor, match_pos, low_prefix_pos);
                }
                let cur_total = cur_forward + cur_backward;
                if cur_total > best_match_length {
                    best_match_length = cur_total;
                    forward_match_length = cur_forward;
                    backward_match_length = cur_backward;
                    best_entry = Some(cur);
                }
            }

            let Some(best) = best_entry else {
                // No match: insert and move on.
                state.insert_entry(hash, new_entry);
                continue;
            };

            // Match found.
            let offset = (split + seg_bias) as u32 - best.offset;
            let m_length = forward_match_length + backward_match_length;
            if seqs.len() == capacity {
                // `dstSize_tooSmall` — cannot happen with the per-block
                // capacity of blockSize / minMatchLength, kept for fidelity.
                return Err(Error::Encode("LDM sequence storage exhausted"));
            }
            seqs.push(RawSeq {
                lit_length: (split - backward_match_length - anchor) as u32,
                match_length: m_length as u32,
                offset,
            });

            // Inserted after the search to avoid clobbering bestEntry.
            state.insert_entry(hash, new_entry);

            anchor = split + forward_match_length;

            // Repeating overlapping pattern: skip over the overlapping
            // matches, re-seeding the rolling hash at the anchor.
            if anchor > ip + hashed {
                hash_state.reset(data, anchor - min_match_length, min_match_length);
                // Continue the outer loop at anchor (ip + hashed == anchor).
                ip = anchor - hashed;
                break;
            }
        }

        ip += hashed;
    }

    Ok(iend - anchor)
}

/// `ZSTD_ldm_generateSequences`: chunked driver around the internal
/// generator, enforcing the maximum match distance per chunk. The caller
/// must already have registered `data[chunk_start..chunk_end]` with
/// [`LdmState::window`].
pub(crate) fn generate_sequences(
    state: &mut LdmState,
    seqs: &mut Vec<RawSeq>,
    capacity: usize,
    data: &[u8],
    chunk_start: usize,
    chunk_end: usize,
) -> Result<(), Error> {
    let max_dist = 1u32 << state.params.window_log;
    let src_size = chunk_end - chunk_start;
    let nb_chunks = src_size / K_MAX_CHUNK_SIZE + usize::from(src_size % K_MAX_CHUNK_SIZE != 0);
    let mut leftover_size = 0usize;

    for chunk in 0..nb_chunks {
        if seqs.len() >= capacity {
            break;
        }
        let sub_start = chunk_start + chunk * K_MAX_CHUNK_SIZE;
        let remaining = chunk_end - sub_start;
        let sub_end = if remaining < K_MAX_CHUNK_SIZE {
            chunk_end
        } else {
            sub_start + K_MAX_CHUNK_SIZE
        };
        let prev_size = seqs.len();

        // 1. Overflow correction would run here (`ZSTD_window_canOverflowCorrect`
        //    etc.); unreachable below the frame-level 3500 MiB index gate.
        // 2. Enforce the maximum offset, anchored at the chunk *end* (unlike
        //    the main window's per-block anchor at the block start).
        state
            .window
            .enforce_max_dist((sub_end + state.window.seg_bias as usize) as u32, max_dist);
        // 3. Generate the sequences for the chunk.
        let new_leftover_size =
            generate_sequences_internal(state, seqs, capacity, data, sub_start, sub_end)?;
        // 4. Prepend leftover literals from the previous chunk to the first
        //    newly generated sequence.
        if prev_size < seqs.len() {
            seqs[prev_size].lit_length += leftover_size as u32;
            leftover_size = new_leftover_size;
        } else {
            debug_assert_eq!(new_leftover_size, sub_end - sub_start);
            leftover_size += sub_end - sub_start;
        }
    }
    Ok(())
}
