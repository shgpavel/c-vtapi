# c-vtapi Migration Post-Mortem

The VirusTotal API v3 migration is complete.

What landed:

- Public headers now live under `include/vt/`.
- Public API symbols use the lowercase `vt_` namespace.
- Client, resource, object, iterator, error, and JSON surfaces are v3-native.
- HTTP uses libcurl and sends the API key through the v3 header model.
- JSON parsing and encoding use yyjson.
- Example programs live under `users/v3/` and read `VTAPI_KEY`.
- Meson builds the v3 static library, examples, and available tests directly.
- The build targets C23, with Meson falling back to C2x when needed.

What was retired:

- The transition build flags are gone.
- The obsolete JSON dependency is gone.
- Old example wiring is gone from the root build.
- Architecture handoff notes have been removed from the working tree.

Current build shape:

```sh
meson setup build && meson compile -C build
meson test -C build
```

Network-facing tests remain opt-in through `VTAPI_RUN_NETWORK_TESTS=1`.

This file is kept as a short project record. Detailed coordination notes now
belong in branch and commit history.
