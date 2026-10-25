// Specialized dimensions are checked on the host before pipeline creation.
// One 128-lane workgroup/key; reduction order is (score descending, ordinal ascending).
const WIDTH: u32 = {{WIDTH}}u;
const CACHE_WORDS: u32 = {{CACHE_WORDS}}u;
const CACHE_ROWS: bool = {{CACHE_ROWS}};
const PACKED_COUNTS: bool = {{PACKED_COUNTS}};
// Immutable job facts specialized per pipeline; params keep the same values.
const LENGTH: u32 = {{LENGTH}}u;
const INITIAL_ORDER: u32 = {{INITIAL_ORDER}}u;
const FINAL_ORDER: u32 = {{FINAL_ORDER}}u;
const IDENTICAL: bool = {{IDENTICAL}};
const PAIR_SLICE: u32 = {{PAIR_SLICE}}u;
const LANE_ACTIONS: u32 = {{LANE_ACTIONS}}u;
// False when no symbol is fixed or immutable: mask reads are skipped.
const MASKED: bool = {{MASKED}};
// Scalar-packed private mappings avoid dynamically indexed private-array spills
// on Polaris for alphabets <=32. Wider alphabets keep the general array path.
struct PackedBoard { a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32 }
alias Mapping = {{MAPPING_TYPE}};
{{MAPPING_FUNCTIONS}}
struct Params {
    keys: u32, length: u32, width: u32, row_words: u32,
    max_pairs: u32, backtrack: u32, switch_pairs: u32, fixed_count: u32,
    start_len: u32, identical: u32, initial_order: u32, final_order: u32,
    budget: u32, pair_slice: u32, lane_actions: u32, padding1: u32,
}
// Host wire layout: 16 header words, WIDTH map words, WIDTH ordered-pair words.
struct State {
    score: i64, evaluations: u64, best_score: i64,
    pairs: u32, phase: u32, ascent: u32, initialized: u32,
    done: u32, cursor: u32, best_ordinal: u32, best_pairs: u32,
    board_len: u32, padding: u32,
    mapping: array<u32, WIDTH>, board: array<u32, WIDTH>,
}
struct Candidate { score: i64, ordinal: u32, pairs: u32, count: u32 }
struct Trial { mapping: Mapping, links: u32, valid: bool }
@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> input: array<u32>;
@group(0) @binding(2) var<storage, read> rows: array<u32>;
@group(0) @binding(3) var<storage, read> initial_weights: array<i64>;
@group(0) @binding(4) var<storage, read> final_weights: array<i64>;
// fixed mask, mutable mask, starting mapping, ordered starting pairs.
@group(0) @binding(5) var<storage, read> job: array<u32>;
@group(0) @binding(6) var<storage, read_write> states: array<State>;
// Keys of this batch that finished; the only per-dispatch readback.
@group(0) @binding(7) var<storage, read_write> finished: atomic<u32>;
var<workgroup> cached_rows: array<u32, CACHE_WORDS>;
var<workgroup> current: State;
var<workgroup> candidates: array<Candidate, 128>;

fn byte_at(key: u32, index: u32) -> u32 {
    var word: u32;
    if (CACHE_ROWS) { word = cached_rows[index / 4u]; }
    else { word = rows[key * params.row_words + index / 4u]; }
    return (word >> ((index % 4u) * 8u)) & 255u;
}

fn load_board() -> Mapping {
    var board: Mapping;
    for (var i = 0u; i < WIDTH; i++) { put(&board, i, current.mapping[i]); }
    return board;
}

// Constant orders per phase let the compiler fold radix, windows and branches.
fn evaluate(key: u32, mapping: Mapping, phase: u32) -> i64 {
    if (phase == 0u) { return score(key, mapping, INITIAL_ORDER, 0u); }
    return score(key, mapping, FINAL_ORDER, 1u);
}

fn score(key: u32, mapping: Mapping, order: u32, phase: u32) -> i64 {
    var counts: array<u32, WIDTH>;
    var small_counts: Mapping;
    var radix = 1u;
    for (var i = 1u; i < order; i++) { radix *= WIDTH; }
    var window = 0u;
    var sum = 0li;
    for (var p = 0u; p < LENGTH; p++) {
        let plain = lookup(mapping, byte_at(key, p * WIDTH + lookup(mapping, input[p])));
        if (order == 0u) {
            if (PACKED_COUNTS) { put(&small_counts, plain, lookup(small_counts, plain) + 1u); }
            else { counts[plain] += 1u; }
        }
        else {
            window = (window % radix) * WIDTH + plain;
            if (p + 1u >= order) {
                if (phase == 0u) { sum += initial_weights[window]; }
                else { sum += final_weights[window]; }
            }
        }
    }
    if (order != 0u) {
        let windows = i64(LENGTH - order + 1u);
        var quotient = sum / windows;
        if (sum < 0li && sum % windows != 0li) { quotient -= 1li; }
        return quotient;
    }
    var pairs = 0lu;
    for (var i = 0u; i < WIDTH; i++) {
        var count = u64(counts[i]);
        if (PACKED_COUNTS) { count = u64(lookup(small_counts, i)); }
        if (count > 0lu) { pairs += count * (count - 1lu); }
    }
    let numerator = pairs * u64(WIDTH);
    let denominator = u64(LENGTH) * u64(LENGTH - 1u);
    // With <=255 letters and <=32 symbols, this product provably fits u64.
    if (PACKED_COUNTS) { return i64(numerator * 4294967296lu / denominator); }
    // Exact Q32 long division, without overflowing a u64 numerator shifted by 32.
    var quotient = numerator / denominator;
    var remainder = numerator % denominator;
    for (var bit = 0u; bit < 32u; bit++) {
        remainder *= 2lu;
        quotient *= 2lu;
        if (remainder >= denominator) { remainder -= denominator; quotient += 1lu; }
    }
    return i64(quotient);
}

fn trial_for(board: Mapping, a: u32, b: u32, action: u32) -> Trial {
    let c = lookup(board, a);
    let d = lookup(board, b);
    let both_free = a == c && b == d;
    var result: Trial;
    result.mapping = board;
    if ((!both_free && current.pairs < params.backtrack)
        || (MASKED && (job[a] != 0u || job[b] != 0u || job[c] != 0u || job[d] != 0u))) { return result; }
    var actions = 4u;
    if (both_free || c == b) { actions = 1u; }
    else if (a == c || b == d) { actions = 2u; }
    if (action >= actions) { return result; }
    var x = a;
    var y = b;
    let z = c;
    var w = d;
    var links = 1u;
    if (both_free) { links = 1u; }
    else if (c == b) { links = 0u; }
    else if (a == c || b == d) {
        if (a == c) { x = a; y = select(b, d, action == 1u); }
        else { x = b; y = select(a, c, action == 1u); }
    } else {
        if (action >= 2u) { y = d; w = b; }
        links = select(1u, 2u, action == 1u || action == 3u);
    }
    let remaining = current.pairs - u32(a != c) - u32(b != d && c != b);
    if (remaining + links > params.max_pairs) { return result; }
    if (MASKED && links > 0u && (job[WIDTH + x] == 0u || job[WIDTH + y] == 0u)) { return result; }
    if (MASKED && links > 1u && (job[WIDTH + z] == 0u || job[WIDTH + w] == 0u)) { return result; }
    // Keep a function-local pointer: Naga 29's SPIR-V writer cannot cache a
    // pointer to a nested struct member passed as a function argument.
    var mapping = board;
    put(&mapping, a, a); put(&mapping, b, b);
    put(&mapping, c, c); put(&mapping, d, d);
    if (links > 0u) { put(&mapping, x, y); put(&mapping, y, x); }
    if (links > 1u) { put(&mapping, z, w); put(&mapping, w, z); }
    result.mapping = mapping;
    result.links = remaining + links;
    result.valid = true;
    return result;
}

fn endpoints(pair_index: u32) -> vec2<u32> {
    var a = 0u;
    var offset = pair_index;
    loop {
        let span = WIDTH - 1u - a;
        if (offset < span) { break; }
        offset -= span;
        a += 1u;
    }
    return vec2(a, a + 1u + offset);
}

@compute @workgroup_size(128)
fn main(@builtin(workgroup_id) group: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    let key = group.x;
    if (lane == 0u) { current = states[key]; }
    if (workgroupUniformLoad(&current.done) != 0u) { return; }
    if (CACHE_ROWS) {
        for (var i = lane; i < params.row_words; i += 128u) {
            cached_rows[i] = rows[key * params.row_words + i];
        }
    }
    workgroupBarrier();
    if (lane == 0u) {
        if (current.initialized == 0u) {
            for (var i = 0u; i < WIDTH; i++) {
                current.mapping[i] = job[2u * WIDTH + i];
                current.board[i] = job[3u * WIDTH + i];
            }
            current.board_len = params.start_len;
            current.pairs = params.fixed_count + params.start_len;
            current.phase = u32(current.pairs >= params.switch_pairs);
            current.score = evaluate(key, load_board(), current.phase);
            current.evaluations = 1lu;
            current.initialized = 1u;
        }
    }
    workgroupBarrier();
    let pair_count = WIDTH * (WIDTH - 1u) / 2u;
    // A step is a bounded slice of a scan; at most budget full scans can finish.
    for (var step = 0u; step < params.budget; step++) {
        if (workgroupUniformLoad(&current.done) != 0u) { break; }
        let board = load_board();
        var best = Candidate(current.score, 0xffffffffu, current.pairs, 0u);
        let end = min(pair_count, current.cursor + PAIR_SLICE);
        // A lane owns lane_actions (4: whole pair, 1: one action slot) consecutive
        // actions. Whole pairs avoid idle lanes in add-only scans, where only
        // action 0 is legal. Ordinals keep the CPU emission order either way.
        let per_pair = 4u / LANE_ACTIONS;
        for (var unit = current.cursor * per_pair + lane; unit < end * per_pair; unit += 128u) {
            let pair = unit / per_pair;
            let ab = endpoints(pair);
            let first = (unit % per_pair) * LANE_ACTIONS;
            for (var action = first; action < first + LANE_ACTIONS; action++) {
                let trial = trial_for(board, ab.x, ab.y, action);
                if (!trial.valid) { continue; }
                let ordinal = pair * 4u + action;
                let score = evaluate(key, trial.mapping, current.phase);
                best.count += 1u;
                if (score > best.score || (score == best.score && ordinal < best.ordinal)) {
                    best.score = score; best.ordinal = ordinal; best.pairs = trial.links;
                }
            }
        }
        candidates[lane] = best;
        workgroupBarrier();
        for (var stride = 64u; stride > 0u; stride /= 2u) {
            if (lane < stride) {
                let own = candidates[lane];
                let other = candidates[lane + stride];
                if (other.score > own.score || (other.score == own.score && other.ordinal < own.ordinal)) {
                    candidates[lane] = other;
                }
                candidates[lane].count = own.count + other.count;
            }
            workgroupBarrier();
        }
        if (lane == 0u) {
            let winner = candidates[0];
            if (current.cursor == 0u) {
                current.best_score = current.score;
                current.best_ordinal = 0xffffffffu;
                current.best_pairs = current.pairs;
            }
            current.evaluations += u64(winner.count);
            if (winner.score > current.best_score || (winner.score == current.best_score && winner.ordinal < current.best_ordinal)) {
                current.best_score = winner.score;
                current.best_ordinal = winner.ordinal;
                current.best_pairs = winner.pairs;
            }
            current.cursor = end;
            if (end == pair_count) {
                current.ascent |= u32(current.phase != 0u || IDENTICAL);
                current.cursor = 0u;
                if (current.best_score <= current.score) {
                    current.done = 1u;
                    atomicAdd(&finished, 1u);
                    if (current.phase == 0u && !IDENTICAL) {
                        current.score = evaluate(key, board, 1u);
                        current.evaluations += 1lu;
                    }
                } else {
                    let ab = endpoints(current.best_ordinal / 4u);
                    let trial = trial_for(board, ab.x, ab.y, current.best_ordinal % 4u);
                    for (var i = 0u; i < WIDTH; i++) { current.mapping[i] = lookup(trial.mapping, i); }
                    current.pairs = current.best_pairs;
                    current.score = current.best_score;
                    // CPU winner_board canonicalizes in alphabet order, unlike an
                    // untouched starting board whose order/orientation is retained.
                    current.board_len = 0u;
                    for (var i = 0u; i < WIDTH; i++) {
                        if (i < current.mapping[i] && job[i] == 0u) {
                            current.board[current.board_len] = i | (current.mapping[i] << 8u);
                            current.board_len += 1u;
                        }
                    }
                    if (current.phase == 0u && current.pairs >= params.switch_pairs) {
                        current.phase = 1u;
                        if (!IDENTICAL) {
                            current.score = evaluate(key, trial.mapping, 1u);
                            current.evaluations += 1lu;
                        }
                    }
                }
            }
        }
        workgroupBarrier();
    }
    if (lane == 0u) { states[key] = current; }
}
