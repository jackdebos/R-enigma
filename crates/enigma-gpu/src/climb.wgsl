// Specialized dimensions are checked on the host before pipeline creation.
// One 128-lane workgroup/(key, seed); reduction is (score descending, ordinal ascending).
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
// Long texts: all lanes share each evaluation, COOP_LETTERS positions per lane and
// round, COOP_ROUNDS rounds per dispatch; partial sums/counts persist in State.
const COOPERATIVE: bool = {{COOPERATIVE}};
const COOP_LETTERS: u32 = {{COOP_LETTERS}}u;
const COOP_ROUNDS: u32 = {{COOP_ROUNDS}}u;
// WIDTH rounded up to even keeps the State stride a multiple of eight bytes.
const COUNT_WORDS: u32 = {{COUNT_WORDS}}u;
// Order code of the entropy objective (IC is 0, n-grams 1-6). Its weight table
// holds [high, low] per count: term(count) = high * 2^16 + low, 0 <= low < 2^16.
const ENTROPY: u32 = 7u;
const TRIE: u32 = 8u;
// Pending cooperative evaluation kinds.
const EVAL_NONE: u32 = 0u;
const EVAL_INITIAL: u32 = 1u;
const EVAL_TRIAL: u32 = 2u;
const EVAL_SWITCH: u32 = 3u;
const EVAL_FINAL: u32 = 4u;
// Scalar-packed private mappings avoid dynamically indexed private-array spills
// on Polaris for alphabets <=32. Wider alphabets keep the general array path.
struct PackedBoard { a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32 }
alias Mapping = {{MAPPING_TYPE}};
{{MAPPING_FUNCTIONS}}
struct Params {
    keys: u32, length: u32, width: u32, row_words: u32,
    max_pairs: u32, backtrack: u32, switch_pairs: u32, fixed_count: u32,
    seeds: u32, identical: u32, initial_order: u32, final_order: u32,
    budget: u32, pair_slice: u32, lane_actions: u32, first_seed: u32,
}
// Host wire layout: 24 header words, WIDTH map words, WIDTH ordered-pair words,
// COUNT_WORDS partial histogram words. Cooperative mode alone uses partial..counts;
// its cursor is the next action ordinal to search instead of a pair index.
struct State {
    score: i64, evaluations: u64, best_score: i64,
    pairs: u32, phase: u32, ascent: u32, initialized: u32,
    done: u32, cursor: u32, best_ordinal: u32, best_pairs: u32,
    board_len: u32, padding: u32,
    partial: i64, pending: u32, position: u32, ordinal: u32,
    padding1: u32, padding2: u32, padding3: u32,
    mapping: array<u32, WIDTH>, board: array<u32, WIDTH>, counts: array<u32, COUNT_WORDS>,
}
struct Candidate { score: i64, ordinal: u32, pairs: u32, count: u32 }
struct Trial { mapping: Mapping, links: u32, valid: bool }
@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> input: array<u32>;
@group(0) @binding(2) var<storage, read> rows: array<u32>;
@group(0) @binding(3) var<storage, read> initial_weights: array<i64>;
@group(0) @binding(4) var<storage, read> final_weights: array<i64>;
// Fixed mask, mutable mask, then per seed: length, mapping, ordered pairs.
@group(0) @binding(5) var<storage, read> job: array<u32>;
@group(0) @binding(6) var<storage, read_write> states: array<State>;
// Keys of this batch that finished; the only per-dispatch readback.
@group(0) @binding(7) var<storage, read_write> finished: atomic<u32>;
var<workgroup> cached_rows: array<u32, CACHE_WORDS>;
var<workgroup> current: State;
var<workgroup> candidates: array<Candidate, 128>;
var<workgroup> hist: array<atomic<u32>, WIDTH>;
var<workgroup> next_trial: atomic<u32>;

fn byte_at(key: u32, index: u32) -> u32 {
    var word: u32;
    if (CACHE_ROWS) { word = cached_rows[index / 4u]; }
    else { word = rows[key * params.row_words + index / 4u]; }
    return (word >> ((index % 4u) * 8u)) & 255u;
}

fn decode(key: u32, mapping: Mapping, p: u32) -> u32 {
    return lookup(mapping, byte_at(key, p * WIDTH + lookup(mapping, input[p])));
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

fn is_ngram(order: u32) -> bool { return order > 0u && order < ENTROPY; }

fn weight(phase: u32, index: u32) -> i64 {
    if (phase == 0u) { return initial_weights[index]; }
    return final_weights[index];
}

// Histogram objectives (IC, entropy) from final symbol counts.
struct Histogram { pairs: u64, high: i64, low: i64 }

fn add_count(total: ptr<function, Histogram>, count: u32, order: u32, phase: u32) {
    if (count == 0u) { return; }
    (*total).pairs += u64(count) * u64(count - 1u);
    if (order == ENTROPY) {
        (*total).high += weight(phase, 2u * count);
        (*total).low += weight(phase, 2u * count + 1u);
    }
}

fn histogram_quotient(total: Histogram, order: u32) -> i64 {
    if (order == ENTROPY) { return entropy_quotient(total.high, total.low); }
    return ic_quotient(total.pairs);
}

// Ranking -floor(sum(terms) / (LENGTH * 2^16)), using the exact high/low split:
// floor((H * 2^16 + L) / (N * 2^16)) = floor((H + floor(L / 2^16)) / N), L >= 0.
fn entropy_quotient(high: i64, low: i64) -> i64 {
    let numerator = high + (low >> 16u);
    let length = i64(LENGTH);
    var measured = numerator / length;
    if (numerator < 0li && numerator % length != 0li) { measured -= 1li; }
    return -measured;
}

// Each lane owns start positions, not decoded positions: walks may cross its
// range. Every terminal (including prefixes and overlapping words) contributes.
// Raw sums fit i64; the host scales the final trie score to Q32 in i128.
fn trie_chunk(key: u32, mapping: Mapping, phase: u32, start: u32, end: u32) -> i64 {
    let depth = u32(weight(phase, 0u));
    let edges = u32(weight(phase, 1u));
    var sum = 0li;
    for (var p = start; p < end; p++) {
        var node = 0u;
        for (var q = p; q < min(LENGTH, p + depth); q++) {
            let symbol = decode(key, mapping, q);
            let base = 2u + 3u * node;
            let first = u32(weight(phase, base));
            let count = u32(weight(phase, base + 1u));
            var lo = first;
            var hi = first + count;
            loop {
                if (lo >= hi) { break; }
                let mid = lo + (hi - lo) / 2u;
                if (u32(weight(phase, edges + 2u * mid)) < symbol) { lo = mid + 1u; }
                else { hi = mid; }
            }
            if (lo == first + count) { break; }
            let edge = edges + 2u * lo;
            if (u32(weight(phase, edge)) != symbol) { break; }
            node = u32(weight(phase, edge + 1u));
            sum += weight(phase, 2u + 3u * node + 2u);
        }
    }
    return sum;
}

fn score(key: u32, mapping: Mapping, order: u32, phase: u32) -> i64 {
    if (order == TRIE) { return trie_chunk(key, mapping, phase, 0u, LENGTH); }
    var counts: array<u32, WIDTH>;
    var small_counts: Mapping;
    let ngram = is_ngram(order);
    var radix = 1u;
    if (ngram) { for (var i = 1u; i < order; i++) { radix *= WIDTH; } }
    var window = 0u;
    var sum = 0li;
    for (var p = 0u; p < LENGTH; p++) {
        let plain = decode(key, mapping, p);
        if (!ngram) {
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
    if (ngram) { return ngram_quotient(sum, order); }
    var total = Histogram(0lu, 0li, 0li);
    for (var i = 0u; i < WIDTH; i++) {
        var count = counts[i];
        if (PACKED_COUNTS) { count = lookup(small_counts, i); }
        add_count(&total, count, order, phase);
    }
    return histogram_quotient(total, order);
}

fn ngram_quotient(sum: i64, order: u32) -> i64 {
    let windows = i64(LENGTH - order + 1u);
    var quotient = sum / windows;
    if (sum < 0li && sum % windows != 0li) { quotient -= 1li; }
    return quotient;
}

fn ic_quotient(pairs: u64) -> i64 {
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
    let state = group.x;
    let ordinal = params.first_seed + state;
    let key = ordinal / params.seeds;
    let seed = ordinal % params.seeds;
    if (lane == 0u) { current = states[state]; }
    if (workgroupUniformLoad(&current.done) != 0u) { return; }
    if (CACHE_ROWS) {
        for (var i = lane; i < params.row_words; i += 128u) {
            cached_rows[i] = rows[key * params.row_words + i];
        }
    }
    workgroupBarrier();
    if (lane == 0u) {
        if (current.initialized == 0u) {
            let base = 2u * WIDTH + seed * (2u * WIDTH + 1u);
            for (var i = 0u; i < WIDTH; i++) {
                current.mapping[i] = job[base + 1u + i];
                current.board[i] = job[base + 1u + WIDTH + i];
            }
            current.board_len = job[base];
            current.pairs = params.fixed_count + current.board_len;
            current.phase = u32(current.pairs >= params.switch_pairs);
            if (COOPERATIVE) { start_evaluation(EVAL_INITIAL); }
            else {
                current.score = evaluate(key, load_board(), current.phase);
                current.evaluations = 1lu;
            }
            current.initialized = 1u;
        }
    }
    workgroupBarrier();
    // The host emits only the specialized path: unused workgroup storage of the
    // other path would otherwise still be allocated and zero-initialized.
    {{CLIMB}}(key, lane);
    if (lane == 0u) { states[state] = current; }
}

// Short texts: each lane evaluates whole trials of a bounded scan slice.
fn sliced(key: u32, lane: u32) {
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
                let rescore = end_scan(board);
                if (rescore != EVAL_NONE) {
                    current.score = evaluate(key, load_board(), 1u);
                    current.evaluations += 1lu;
                }
                if (rescore == EVAL_FINAL) { finish_climb(); }
            }
        }
        workgroupBarrier();
    }
}

fn finish_climb() {
    current.done = 1u;
    atomicAdd(&finished, 1u);
}

// Lane 0, after a complete scan: commit its winner or stop. Returns the final-
// objective rescore the CPU charges next (switch or final), if any.
fn end_scan(board: Mapping) -> u32 {
    current.ascent |= u32(current.phase != 0u || IDENTICAL);
    current.cursor = 0u;
    if (current.best_score <= current.score) {
        if (current.phase == 0u && !IDENTICAL) { return EVAL_FINAL; }
        finish_climb();
        return EVAL_NONE;
    }
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
        if (!IDENTICAL) { return EVAL_SWITCH; }
    }
    return EVAL_NONE;
}

fn start_evaluation(kind: u32) {
    current.pending = kind;
    current.position = 0u;
    current.partial = 0li;
}

// Lane 0: apply one finished evaluation exactly as the CPU walker would.
fn complete_evaluation(kind: u32, value: i64, links: u32) {
    current.pending = EVAL_NONE;
    current.evaluations += 1lu;
    if (kind == EVAL_TRIAL) {
        if (value > current.best_score || (value == current.best_score && current.ordinal < current.best_ordinal)) {
            current.best_score = value;
            current.best_ordinal = current.ordinal;
            current.best_pairs = links;
        }
        return;
    }
    current.score = value;
    if (kind == EVAL_FINAL) { finish_climb(); }
}

fn sum_lanes(lane: u32, value: i64) -> i64 {
    candidates[lane].score = value;
    workgroupBarrier();
    for (var stride = 64u; stride > 0u; stride /= 2u) {
        if (lane < stride) { candidates[lane].score += candidates[lane + stride].score; }
        workgroupBarrier();
    }
    return candidates[0].score;
}

// Window sums for windows ending in [start, end); IC counts go to `hist`.
fn partial_score(key: u32, mapping: Mapping, phase: u32, start: u32, end: u32) -> i64 {
    if (phase == 0u) { return chunk(key, mapping, INITIAL_ORDER, 0u, start, end); }
    return chunk(key, mapping, FINAL_ORDER, 1u, start, end);
}

fn chunk(key: u32, mapping: Mapping, order: u32, phase: u32, start: u32, end: u32) -> i64 {
    if (order == TRIE) { return trie_chunk(key, mapping, phase, start, end); }
    let ngram = is_ngram(order);
    var radix = 1u;
    if (ngram) { for (var i = 1u; i < order; i++) { radix *= WIDTH; } }
    // Re-decode the order-1 letters before start; every position decodes alone.
    var first = start;
    if (ngram && order > 1u) { first = start - min(start, order - 1u); }
    var window = 0u;
    var sum = 0li;
    for (var p = first; p < end; p++) {
        let plain = decode(key, mapping, p);
        if (!ngram) { atomicAdd(&hist[plain], 1u); }
        else {
            window = (window % radix) * WIDTH + plain;
            if (p >= start && p + 1u >= order) {
                if (phase == 0u) { sum += initial_weights[window]; }
                else { sum += final_weights[window]; }
            }
        }
    }
    return sum;
}

// Long texts: the workgroup searches the next legal trial in ordinal order, then
// evaluates it together across rounds and dispatches. Integer partial sums and
// counts are associative, so the split cannot change any score.
fn cooperative(key: u32, lane: u32) {
    let actions = 2u * WIDTH * (WIDTH - 1u);
    for (var i = lane; i < WIDTH; i += 128u) { atomicStore(&hist[i], current.counts[i]); }
    var lane_sum = 0li;
    for (var round = 0u; round < COOP_ROUNDS; round++) {
        workgroupBarrier();
        if (workgroupUniformLoad(&current.done) != 0u) { break; }
        let pending = workgroupUniformLoad(&current.pending);
        let board = load_board();
        if (pending == EVAL_NONE) {
            if (lane == 0u) { atomicStore(&next_trial, 0xffffffffu); }
            workgroupBarrier();
            let ordinal = current.cursor + lane;
            if (ordinal < actions) {
                let ab = endpoints(ordinal / 4u);
                if (trial_for(board, ab.x, ab.y, ordinal % 4u).valid) { atomicMin(&next_trial, ordinal); }
            }
            workgroupBarrier();
            if (lane == 0u) {
                if (current.cursor == 0u) {
                    current.best_score = current.score;
                    current.best_ordinal = 0xffffffffu;
                    current.best_pairs = current.pairs;
                }
                let found = atomicLoad(&next_trial);
                if (found != 0xffffffffu) {
                    start_evaluation(EVAL_TRIAL);
                    current.ordinal = found;
                    current.cursor = found + 1u;
                } else if (current.cursor + 128u >= actions) {
                    start_evaluation(end_scan(board));
                } else {
                    current.cursor += 128u;
                }
            }
            continue;
        }
        let phase = select(current.phase, 1u, pending >= EVAL_SWITCH);
        var mapping = board;
        var links = 0u;
        if (pending == EVAL_TRIAL) {
            let ab = endpoints(current.ordinal / 4u);
            let trial = trial_for(board, ab.x, ab.y, current.ordinal % 4u);
            mapping = trial.mapping;
            links = trial.links;
        }
        let base = workgroupUniformLoad(&current.position);
        let start = min(base + lane * COOP_LETTERS, LENGTH);
        lane_sum += partial_score(key, mapping, phase, start, min(start + COOP_LETTERS, LENGTH));
        let next = base + 128u * COOP_LETTERS;
        if (next < LENGTH) {
            workgroupBarrier();
            if (lane == 0u) { current.position = next; }
            continue;
        }
        let total = sum_lanes(lane, lane_sum);
        lane_sum = 0li;
        if (lane == 0u) {
            let order = select(INITIAL_ORDER, FINAL_ORDER, phase != 0u);
            var value = 0li;
            if (order == TRIE) {
                value = total + current.partial;
            } else if (!is_ngram(order)) {
                var total = Histogram(0lu, 0li, 0li);
                for (var i = 0u; i < WIDTH; i++) {
                    add_count(&total, atomicLoad(&hist[i]), order, phase);
                }
                value = histogram_quotient(total, order);
            } else {
                value = ngram_quotient(total + current.partial, order);
            }
            complete_evaluation(pending, value, links);
        }
        workgroupBarrier();
        for (var i = lane; i < WIDTH; i += 128u) { atomicStore(&hist[i], 0u); }
    }
    workgroupBarrier();
    let carried = sum_lanes(lane, lane_sum);
    if (lane == 0u) { current.partial += carried; }
    for (var i = lane; i < WIDTH; i += 128u) { current.counts[i] = atomicLoad(&hist[i]); }
    workgroupBarrier();
}
