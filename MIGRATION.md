# c-vtapi → VirusTotal API v3 migration

Shared ground rules. All agents must follow.

## Scope
Modernize this client end-to-end:
- Drop VT API v2 surface (`https://www.virustotal.com/vtapi/v2/...`).
- Target VT API v3 (`https://www.virustotal.com/api/v3/...`). Spec: <https://docs.virustotal.com/reference/overview>.
- Replace jansson with **yyjson** (fastest pure-C JSON, MIT, header+single-source).
- Bump language to **C23** (`c_std=c2x` if `c23` unsupported by toolchain — detect in meson).
- Keep meson as the only build system. No autotools, no CMake.

## Auth
- Header `x-apikey: <APIKEY>` on every request.
- Read key from env `VTAPI_KEY` in examples; library never reads env, takes key as ctor arg.

## Wire model
v3 responses are JSON envelopes:
```
{ "data": { "id": "...", "type": "...", "attributes": {...}, "relationships": {...}, "links": {...} },
  "meta": { "cursor": "..." } }
```
or `{ "data": [ ... ], "meta": {...}, "links": {...} }` for collections.

Errors:
```
{ "error": { "code": "NotFoundError", "message": "..." } }
```

## Public API namespace
All new public symbols prefixed `vt_` (lowercase, snake_case). All public headers under `include/vt/`. Keep old `include/Vt*.h` *untouched* during migration so the v2 build still compiles until cutover.

## Layout (target)
```
include/vt/
    client.h          # vt_client, transport, auth
    error.h           # vt_error, vt_status
    object.h          # vt_object envelope (data/attributes/relationships)
    iter.h            # vt_iter pagination cursor
    files.h
    urls.h
    domains.h
    ip_addresses.h
    analyses.h
    json.h            # yyjson re-export / helpers (internal-ish)
lib/v3/
    client.c
    http.c
    json.c
    files.c
    urls.c
    domains.c
    ip_addresses.c
    analyses.c
    error.c
subprojects/
    yyjson.wrap       # meson wrap for yyjson
users/v3/
    *.c               # ported example tools
```

Old `lib/Vt*.c` and `users/*.c` stay until **Phase 3 cutover**.

## Conventions
- Opaque types: forward-declare in headers, define in `.c`. Hand out `vt_client *`, never struct internals.
- Errors: every fallible function returns `vt_status` (enum). Output via out-params. `vt_error_last(client)` for detailed message.
- Memory: caller frees what library allocates via dedicated `vt_xxx_free()`. No `free()` on opaque ptrs.
- Threading: client not thread-safe by default; document. Multiple clients = multiple curl handles.
- No globals. No static state besides curl_global_init refcount.
- Clang-format already configured — run on every file you touch.

## yyjson integration
- Wrap via meson subproject. Pin a release tag (latest stable as of 2026-05).
- Never expose yyjson types in public headers. Hide behind `vt_json` opaque facade if needed.
- Use mutable doc only when building POST bodies; use immutable doc for parsing responses.

## Coordination
Each agent works in its own worktree on its own branch (`agent/<role>`). Do not touch files outside your scope. If you need a symbol that another agent owns, define a forward declaration / TODO and continue.

Branches:
- `agent/architect` — defines headers + skeleton, **runs first**, lands first
- `agent/http-core`, `agent/resources`, `agent/json-yyjson`, `agent/build-examples` — run in parallel after architect lands

Phase 3 (team-lead review): merge order architect → json → http-core → resources → build-examples.

## Don't
- Don't break the old v2 build during Phase 1/2. Old code stays until cutover.
- Don't add new dependencies beyond libcurl + yyjson without flagging in BRIEF reply.
- Don't write README/docs unless your brief says so.
- Don't commit with Co-Authored-By trailers.
