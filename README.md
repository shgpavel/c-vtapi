# c-vtapi

c-vtapi is a C client for the VirusTotal API v3. The migration keeps the legacy
API v2 build available during the transition, while new code is built around the
`vt_` namespace, C23, libcurl, and yyjson.

## Build

Install Meson, Ninja, pkg-config, libcurl, and yyjson, then build the v3 client:

```sh
meson setup build -Dvt_v3=true -Dvt_v2_legacy=false
meson compile -C build
meson test -C build
meson install -C build
```

To keep the legacy v2 library and examples in the same build, leave
`-Dvt_v2_legacy=true` enabled.

## Examples

The v3 examples live under `users/v3/` and read the API key from `VTAPI_KEY`.
When built with `-Dvt_v2_legacy=false`, Meson builds them as `vt3_*` binaries:

```sh
export VTAPI_KEY=your-api-key
./build/vt3_ip 8.8.8.8
./build/vt3_scan ./sample.bin
./build/vt3_url https://example.com/
```

## Quickstart

```c
#include <stdio.h>
#include <stdlib.h>
#include <vt/vt.h>

int main(void) {
        const char* api_key = getenv("VTAPI_KEY");
        vt_client* client = vt_client_new(api_key);
        vt_object* file = NULL;
        vt_status status;

        if (client == NULL) {
                return 1;
        }

        status = vt_files_get(client, "44d88612fea8a8f36de82e1278abb02f", &file);
        if (status != VT_OK) {
                fprintf(stderr, "%s\n", vt_status_str(status));
                vt_client_free(client);
                return 1;
        }

        printf("%s\n", vt_object_attribute(file, "last_analysis_stats"));

        vt_object_free(file);
        vt_client_free(client);
        return 0;
}
```

See `MIGRATION.md` for the v2 to v3 migration status and coordination rules.
