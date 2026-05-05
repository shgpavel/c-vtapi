# Architect Notes

## Scope

This pass adds the v3 public API skeleton without wiring it into the root
Meson build. The v2 headers, v2 sources, and existing users are untouched.

## API Shape

- Public headers live under `include/vt/` and are collected by
  `include/vt/vt.h`.
- Public handles are opaque: `vt_client`, `vt_object`, `vt_iter`, and
  `vt_json`.
- Fallible APIs return `vt_status` and write results through out-params.
- `VT_UNIMPL` is included in `vt_status` because the architect skeleton needs
  a stable status for unimplemented stubs.
- Object accessors expose only string/count placeholders for `id`, `type`,
  `attributes`, `relationships`, and `links`; no yyjson type appears in public
  headers.

## HTTP And JSON Hooks

- `vt_client_set_transport()` accepts a callback with opaque request/response
  types so the HTTP agent can attach the libcurl implementation without
  changing the public client API.
- `lib/v3/http.h` is internal scaffolding for the default transport.
- `include/vt/json.h` is an opaque facade for the yyjson agent. It intentionally
  does not expose yyjson symbols.

## Build Handoff

`lib/v3/meson.build` defines `v3_sources` only. The build agent can include that
snippet and decide how to combine the new sources with C23 detection and the
yyjson wrap.
