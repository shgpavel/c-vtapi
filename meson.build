project('c-vtapi', 'c',
        version: '1.0.0',
        license: 'Apache-2.0',
        # 1.4.0 is the first meson that knows c_std=c23
        meson_version: '>=1.4.0',
        default_options: [
          # C23; c2x is the fallback for compilers that do not know
          # -std=c23 yet, e.g. gcc 13
          'c_std=c23,c2x',
          'warning_level=3',        # -Wall -Wextra -Wpedantic
          'werror=true',
          'default_library=static', # libcvtapi.a as before
          'b_ndebug=if-release',
        ])

cc = meson.get_compiler('c')

extra_warnings = [
  '-Wcast-align', '-Wclobbered', '-Wempty-body', '-Wfloat-equal',
  '-Wformat-nonliteral', '-Wformat-security', '-Wignored-qualifiers',
  '-Wimplicit-fallthrough', '-Winit-self', '-Wlogical-op',
  '-Wmissing-declarations', '-Wmissing-field-initializers',
  '-Wmissing-parameter-type', '-Wmissing-prototypes',
  '-Wold-style-declaration', '-Woverride-init', '-Wpointer-arith',
  '-Wredundant-decls', '-Wshadow', '-Wsign-compare', '-Wstrict-aliasing',
  '-Wstrict-overflow=5', '-Wstrict-prototypes', '-Wtype-limits',
  '-Wuninitialized', '-Wunused-but-set-parameter', '-Wunused-parameter',
  '-Wunused-result', '-Wwrite-strings',
]
add_project_arguments(cc.get_supported_arguments(extra_warnings),
                      '-D_POSIX_C_SOURCE=200809L',
                      language: 'c')

jansson_dep = dependency('jansson', version: '>=2.14')
# >= 7.85: CURLOPT_PROTOCOLS_STR / CURLOPT_REDIR_PROTOCOLS_STR (and the
# thread-safe curl_global_init of 7.84, see src/core.c)
curl_dep = dependency('libcurl', version: '>=7.85.0')
thread_dep = dependency('threads')

inc = include_directories('include')

# The version macros of the installed header must match the project.
header_version = []
foreach part : ['MAJOR', 'MINOR', 'PATCH']
  header_version += cc.get_define('VT_VERSION_' + part,
                                  prefix: '#include <vt/vt.h>',
                                  include_directories: inc,
                                  dependencies: jansson_dep)
endforeach
if '.'.join(header_version) != meson.project_version()
  error('include/vt/vt.h is version ' + '.'.join(header_version) +
        ' but the project is ' + meson.project_version())
endif

libvt = library('cvtapi',
  'src/buf.c', 'src/core.c', 'src/perform.c',
  'src/file.c', 'src/lookup.c', 'src/dist.c',
  include_directories: inc,
  dependencies: [jansson_dep, curl_dep, thread_dep],
  gnu_symbol_visibility: 'hidden',
  version: meson.project_version(),
  soversion: '1',
  install: true)

vt_dep = declare_dependency(include_directories: inc, link_with: libvt,
                            dependencies: [jansson_dep])
meson.override_dependency('cvtapi', vt_dep)

install_headers('include/vt/vt.h', subdir: 'vt')

pkg = import('pkgconfig')
pkg.generate(libvt,
  name: 'cvtapi',
  description: 'C client for the VirusTotal v2 API',
  requires: ['jansson'],        # vt.h includes <jansson.h>
  requires_private: ['libcurl'])

# Command-line tools.  Not installed: generic names such as `ip` or `url`
# would shadow system tools.
common_lib = static_library('vtcommon', 'imp/common.c',
                            dependencies: vt_dep)
vt_tools = {}
foreach t : ['scan', 'search', 'ip', 'domain_report', 'url', 'comments',
             'file_dist', 'url_dist']
  vt_tools += {t: executable(t, 'imp/' + t + '.c', link_with: common_lib,
                             dependencies: vt_dep, install: false)}
endforeach

if get_option('tests')
  subdir('tests')
endif
