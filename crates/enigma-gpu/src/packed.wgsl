// Mapping specialization for any alphabet of at most 32 symbols.
fn lookup(board: Mapping, index: u32) -> u32 {
    var word = board.h;
    switch (index / 4u) {
        case 0u: { word = board.a; }
        case 1u: { word = board.b; }
        case 2u: { word = board.c; }
        case 3u: { word = board.d; }
        case 4u: { word = board.e; }
        case 5u: { word = board.f; }
        case 6u: { word = board.g; }
        default: {}
    }
    return (word >> ((index % 4u) * 8u)) & 255u;
}
fn put(board: ptr<function, Mapping>, index: u32, value: u32) {
    let shift = (index % 4u) * 8u;
    let mask = ~(255u << shift);
    let bits = value << shift;
    switch (index / 4u) {
        case 0u: { (*board).a = ((*board).a & mask) | bits; }
        case 1u: { (*board).b = ((*board).b & mask) | bits; }
        case 2u: { (*board).c = ((*board).c & mask) | bits; }
        case 3u: { (*board).d = ((*board).d & mask) | bits; }
        case 4u: { (*board).e = ((*board).e & mask) | bits; }
        case 5u: { (*board).f = ((*board).f & mask) | bits; }
        case 6u: { (*board).g = ((*board).g & mask) | bits; }
        default: { (*board).h = ((*board).h & mask) | bits; }
    }
}
