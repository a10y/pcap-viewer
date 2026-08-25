# pcap·analyze

A static, local-first PCAP viewer built with Rust, WebAssembly, and WebGPU. Capture bytes stay in the browser. There is no application server and no upload endpoint.

## Current scaffold

- Reads `PCAP` and `PCAPNG` files as bounded stream chunks in a module worker.
- Parses records incrementally and reports byte progress to the status bar.
- Handles PCAP byte order and microsecond/nanosecond timestamps.
- Handles PCAPNG sections, interface link types, and `if_tsresol`/`if_tsoffset` timestamp options.
- Decodes Ethernet, VLAN, ARP, IPv4, IPv6, TCP, and UDP metadata.
- Indexes time-ordered packet rows and bidirectional TCP/UDP transport flows.
- Detects cleartext HTTP/1, the HTTP/2 connection preface, TLS, DNS, DHCP, QUIC, mDNS, SSH, and ICMP.
- Associates IP and MAC addresses into host entities when ARP provides explicit mapping evidence.
- Uses WebGPU for virtualized row geometry. Only visible text rows exist in the DOM.
- Provides a Canvas2D fallback when WebGPU is not available.
- Provides flow detail, clickable addresses, host hover summaries, and host entity detail.
- Builds to a relative-path static bundle for GitHub Pages or Cloudflare Pages.

## Architecture

```text
Browser main thread                     Parser module worker
┌───────────────────────────┐          ┌──────────────────────────┐
│ drop target + navigation  │  File    │ bounded File.slice()     │
│ visible-row DOM overlay   │ ───────▶ │ wasm Analyzer            │
│ wasm WebGpuRenderer       │          │ capture framing + decode │
│ flow/entity detail panels │ ◀─────── │ compact Rust indexes     │
└───────────────────────────┘  pages   └──────────────────────────┘
```

Rust code has these seams:

- `src/capture.rs`: incremental PCAP/PCAPNG framing and timestamp normalization.
- `src/decode.rs`: packet protocol decoding and application hints.
- `src/model.rs`: append-only rows, transport flows, entities, and paged queries.
- `src/render.rs`: WebGPU canvas surface and visible-row geometry.
- `src/lib.rs`: narrow `wasm-bindgen` API used by the worker and main thread.

The worker owns the `File` and the analyzer. Main-thread requests are paged, so the full index is not copied into JavaScript.

## Prerequisites

- Rust stable
- `wasm32-unknown-unknown`: `rustup target add wasm32-unknown-unknown`
- `wasm-pack`: `cargo install wasm-pack`
- Python 3 for the included development server, or any static HTTP server

## Develop

```bash
rustup target add wasm32-unknown-unknown
./scripts/dev.sh
# open http://127.0.0.1:8080
```

A `file://` URL does not work because browsers require HTTP for module workers and WASM.

## Validate and build

```bash
cargo test                         # native parser/index tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown
./scripts/build.sh                 # release output in dist/
```

## Deploy

### GitHub Pages

1. Push to `main`.
2. In the repository settings, select **GitHub Actions** as the Pages source.
3. `.github/workflows/pages.yml` builds and deploys `dist/`.

All browser asset paths are relative, so repository subpaths work.

### Cloudflare Pages

Cloudflare's build image must provide Rust, the `wasm32-unknown-unknown` target, and `wasm-pack`. If those tools are available, use:

- Build command: `rustup target add wasm32-unknown-unknown && cargo install wasm-pack --locked && ./scripts/build.sh`
- Build output directory: `dist`

For faster and more reproducible deploys, build in CI or locally and upload the static output with Wrangler:

```bash
./scripts/build.sh
npx wrangler pages deploy dist
```

## Important limits

This is a functional scaffold, not a complete packet-analysis engine.

- A transport flow currently represents one bidirectional 5-tuple. HTTP/1 transactions are detected but are not split into separate request/response application flows.
- HTTP/2 support currently detects a cleartext connection preface. It does not perform HPACK decoding or create per-stream transactions.
- TLS payloads remain opaque. The app does not accept key logs or decrypt TLS.
- TCP sequence reassembly, retransmission handling, IPv4 fragment reassembly, capture-interface clock alignment, index eviction, and persistent indexes are future layers.
- Ethernet and raw-IP link types are supported. Other PCAP/PCAPNG link types are shown as unsupported rows.
- Flow and host detail load associations in pages of 500, so the DOM stays bounded until the user asks for more. The underlying WASM indexes retain the complete associations.
- Metadata still grows with packet count in WASM memory. A production massive-capture path should add fixed-width columnar records, bounded TCP reassembly, and persistent spill to OPFS.

These limits are explicit so encrypted or segmented traffic is not mislabeled as fully decoded HTTP.
