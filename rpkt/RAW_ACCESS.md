# Unchecked generated field access

Generated fields use slice `get_unchecked` / `get_unchecked_mut`, not
fixed-size array views. Checked `parse` validates the fixed contiguous header
and declared lengths once. Ordinary field getters/setters then remain safe;
value-range checks and byte-slice setter length checks are still enforced.
Variable-header and payload slicing remains checked. There is no unchecked
cross-segment read: a header must fit in the current `Pbuf` chunk.

## Buffer contract

Generic packet buffers now require the unsafe `StableBuf: Buf` contract.
`Buf` alone is safe to implement and cannot justify unchecked accesses after
a previous `chunk()` call. `StableBuf` promises that shared access cannot
shrink/move the readable region, that `chunk_mut()` exposes the same region,
and that clones preserve its extent. It adds no runtime check. Implementations
are provided for slices, `Bytes`, `BytesMut`, `Cursor`, `CursorMut`, `&mut T`
where `T: StableBuf`, and DPDK `Pbuf`. Custom buffers must audit and explicitly
implement this contract; see its full safety documentation.

## API migration

- `parse_unchecked` is unsafe. Its current chunk must contain the complete
  fixed header. Before variable-header/payload operations, declared lengths
  must also be valid. Fixed-header templates can be initialized before payload
  is attached; field access alone does not require that payload to exist.
- Generated `set_header_len`, `set_payload_len`, `set_packet_len`, and STP's
  `set_num_of_msti_msg` are unsafe. They do not resize storage. The caller must
  provision valid lengths before accessing variable regions. Generated builders
  establish those obligations internally.
- `*Fields` no longer requires a `Deref<Target = [u8; N]>`. It takes a
  `StableBuf` and validates the fixed-header size at construction. For mutable
  slices use `Ipv4Fields::from_header(CursorMut::new(bytes))`.
- `parse_parts[_mut]` returns slice-backed `*Fields<Cursor[_Mut]>`, options,
  and payload. The disjoint borrows remain disjoint; no fixed-size array cast
  is involved. Parts views still have no structural-length setters.

Regenerate protocols through `pktfmt` / `gen_cmds.sh`; do not hand-edit generated
accessors. `dev/checked_accessor_ablation.sh` is an experimental control that
restores checked accesses in an isolated source archive. It is not a runtime
configuration or the library default.
