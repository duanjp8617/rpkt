# Verus: first buffer-to-packet proof layer

**Status: a verified bounds/reference-model layer, not an end-to-end proof of
the production unsafe Cursor/Pbuf implementations.** No claim is made that
DPDK, mbuf ownership, Rust pointer provenance, or the entire pktfmt compiler
has been formally verified. This distinction is essential when assessing the
ultimate goal: safe access from a parsed packet to its real backing allocation.

The pinned Verus run reports **2169 verified, 0 errors**. Eight deliberately
broken variants are rejected by verification, not merely by Rust parsing.
There are no local `assume`, admitted bodies, or assumed external-function
specifications in the proof inputs; the runner uses `--no-cheating`.

## What is checked

| Layer | Machine-checked result | Remaining gap |
| --- | --- | --- |
| Buffer contract | Generic consumers rely on explicit position, end, contiguous chunk, contents and mutation contracts; both reference implementations discharge them | This is a Verus trait, not verification of every implementation of the external `bytes::Buf` or production `PktBuf` trait |
| Cursor / CursorMut | Region arithmetic and movement/trim/read/write behavior of the executable reference model | Original borrowed allocation, raw pointer operations, lifetimes, indexing/reborrowing and clone refinement |
| Pbuf | Segmented reference traversal, fast/slow movement, byte access, trimming, termination and boundary-segment rebinding; empty segments are allowed | Mapping actual mbuf next pointers/lengths/ownership/freeing to the reference state |
| Shared production code | Bodies of four arithmetic functions in `rpkt/src/buffer_math.rs`; production cursors and Pbuf call these same functions | Production pointer callers' preconditions are still established by manual invariants/tests, not automatically verified |
| Parsed packet | Successful fixed-header parse establishes bounds; reads return the selected byte; writes update only that byte and preserve bounds; release consumes the witness | The production packet wrapper and raw-slice primitives are not directly verified |
| Payload transition | Generic checked header/packet lengths justify trimming followed by advance, preserving payload bytes | Actual protocol length decoding and production payload-method refinement |
| Generated companions | 1007 distinct `(packet/group, read/write, byte range)` certificates, across 119 packet/group modules in all 16 supported protocol files | Endianness, masks, value conversions, custom handwritten code and protocol semantics |

The shared arithmetic functions compile as ordinary Rust without adding a
Verus dependency to rpkt. Verus reads the same source and enables its
specification attributes; normal Cargo compilation erases the attributes.
The source arithmetic and existing runtime assertions are retained. No
performance benefit or exact assembly equivalence is claimed here.

## Central theorem

For a valid buffer with cursor `p`, current contiguous end `c`, and logical
packet end `e`, the contract establishes:

```text
0 <= chunk_start <= p <= c <= e <= backing_storage_length
successful fixed-header parse => H <= c - p
generated field range [a, b)   => 0 <= a <= b <= H
therefore                     => [p + a, p + b) lies in the current chunk
```

`Parsed<B>` owns the model buffer and does not expose mutable cursor access.
Verified byte writes preserve its parse invariant. Obtaining the buffer back
consumes the packet witness, so movement/trimming cannot accidentally reuse a
stale witness in verified code. The proof concerns any implementation of the
formal contract, not just a particular packet length or a sampled input.

`clients.rs` composes actual generated companion functions with the reference
buffers: a successful Cursor-backed Ethernet parse returns the original byte
at offset 12, and a Pbuf-backed field write followed by a read returns the
written value. Parse preserves the source storage/position relation; writes
preserve position and update only the specified byte.

Dynamic length changes do not threaten fixed-field bounds if the storage
extent is unchanged, but they can invalidate options/payload boundaries. The
separate checked `try_payload` transition verifies those new bounds. It does
not assert that all existing generated dynamic-length decoders are correct.

## How pktfmt carries the proof obligations

```sh
cargo run -p pktfmt -- pktfmt/protocols/ipv4.pktfmt \
  -o /tmp/ipv4-runtime.rs --verus /tmp/ipv4-proofs.rs
```

`--verus` is opt-in. Ordinary generated Rust is unchanged. The companion uses
`verification/buffers.rs` and `verification/packet.rs` and contains a checked
fixed-header constructor, range lemmas, and verified byte reads/writes for each
emitted access span. These byte functions are proof companions, **not** a
drop-in implementation of the existing typed IPv4 accessor API.

The extractor parses the actual emitted Rust with `syn`, including combined
field accesses and widened flag loads. Unknown/nonconstant unchecked indices
fail closed. Out-of-bounds constant indices become false proof obligations;
they are not filtered out. Packet constructor linkage additionally checks that
each of the three checked parse methods begins with the expected original
chunk-length guard and rejects short buffers. This syntactic check is a
trusted tool/check, not a proof of arbitrary Rust control flow. Group
discriminator ranges are certified, but the complete group dispatch and
iterator control flow are not verified.

`dev/gen_verus.sh --check` regenerates both outputs, compares the runtime
output against its tracked file, and compares all companions against their
tracked files. Thus an accessor change cannot silently keep an old range
certificate. Handwritten protocol extensions are deliberately excluded.

This is proof-annotated source checked by Verus/SMT, not a portable independently
checkable proof object attached to a compiled binary. Normal Rust consumers
do not automatically become verified by importing rpkt.

## Pbuf correspondence and trusted boundary

The reference Pbuf represents each segment by a cumulative end offset, with
an index replacing each raw `next` pointer. A finite nondecreasing sequence
admits zero-length segments. The model retains a logical flat byte vector
solely to specify contents; **no linearization or copies are added to real
Pbuf processing**.

`seek` mirrors `advance_common` and decreases the number of remaining segments.
The contract also requires an empty chunk if and only if remaining length is
zero. Writing this condition exposed a real production edge case: concatenating
empty mbufs before a nonempty segment made `Pbuf::new` expose an empty chunk
with nonzero remaining length. The new Miri regression failed before the fix
(`[]` instead of `[1, 2, 3]`) and passes after initial empty-segment skipping.
Removing initial normalization from the reference model fails verification.

Forward movement chooses the next segment at a boundary; truncation retains
the first segment whose end reaches the new length. The proof shows that if
the current segment was removed, the cursor equals the new packet end and its
old segment headroom is zero. The production reset condition therefore has a
corresponding proved case in the model. Removing that model reset fails proof.

The unproved concrete-to-model relation still requires:

- Each live `rte_mbuf` belongs to a finite acyclic chain owned exclusively for
  the Pbuf borrow; every `next` pointer targets the correct live successor.
- `data_off`, `data_len`, packet length and segment count accurately describe
  initialized in-allocation storage; cumulative arithmetic does not overflow.
- Slice construction and pointer arithmetic satisfy Rust allocation/provenance,
  alignment, lifetime and aliasing rules. No concurrent DMA, allocator, other
  handle or safe interior mutation invalidates those premises.
- `truncate_to` preserves surviving segments/bytes and frees only the removed
  tail. DPDK and the C wrappers satisfy their ownership contracts.
- The production fast/slow paths implement the reference transitions, including
  all constructors, borrowed subranges and reset cases.

Miri and the new mixed-operation segment test provide runtime evidence for
this relation; tests are **not a refinement proof**. Likewise, source similarity
and shared arithmetic reduce duplication but do not close the relation.

Verus itself explicitly distinguishes verified-client memory safety from
Rust's unsafe-encapsulation guarantee; unverified clients do not inherit a
Verus precondition check. See the official [memory-safety discussion](https://verus-lang.github.io/verus/guide/memory-safety.html).
The toolchain, solver, vstd specifications and the remaining concrete-to-model
mapping are part of the trusted basis; see [trusted components](https://verus-lang.github.io/verus/guide/tcb.html).

## Reproduce

Pinned release: `0.2026.09.20.aef82ed`, commit
`aef82eda71838deef4a8cd0260fda6c9504be9b9`, x86 Linux.
Its Rust toolchain is 1.98.1; the workspace still uses Rust 1.98.0.

Download the corresponding archive from the official
[release](https://github.com/verus-lang/verus/releases/tag/release%2F0.2026.09.20.aef82ed).
The archive SHA-256 is
`7b870fa12bc589015c2fab60a8b3d9f07c7b1adb3444eb0fadffcbf7f0447b33`.
Install Rust 1.98.1 without changing the workspace default, unpack the archive,
and set `VERUS` to its `verus` executable.

```sh
cargo fetch --locked
bash dev/gen_verus.sh             # intentional regeneration only
VERUS=/path/to/verus bash dev/verify_verus.sh
cargo test --locked -p rpkt -p pktfmt
bash dev/check_safety.sh --dpdk   # Miri mock allocation, no NIC/hugepage changes
```

The verification script regenerates in a temporary directory, checks for
drift, verifies all proof inputs, then runs eight negative controls: weakened
parse acceptance, incorrect cursor arithmetic, overrun read, overrun write,
missing Pbuf boundary rebinding, reversed segment-search comparison, missing
initial empty-segment normalization and a
forged Ethernet range. A mutation counts only if Verus reports a verification
error; syntax/type errors do not count. Temporary mutated copies are removed.
CI repeats these checks with the pinned archive and checksum.

## Work remaining for the ultimate claim

1. Introduce tracked allocation/segment permissions and prove a refinement of
   the actual pointer-bearing Cursor/CursorMut/Pbuf methods. Keep the DPDK FFI
   assumptions small and named; do not admit entire buffer implementations.
2. Verify generated parser/accessor bodies directly, including actual decoding,
   group iteration, custom code boundaries, length mutation and constructors.
   Replace the current syntactic linkage checks with verified shared code or a
   formally justified translation.
3. Prove the public safe API maintains the invariant for **unverified Rust
   callers**, not only verified clients. Audit every buffer escape, mutable
   slice, clone and unchecked constructor before claiming unsafe encapsulation.

This first PR establishes useful mechanically checked obligations and catches
several classes of regressions, but it does not complete those three steps.
