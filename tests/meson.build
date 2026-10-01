fs = import('fs')

# Library-level driver of the wire-level tests (not installed).
vtprobe_exe = executable('vtprobe', 'vtprobe.c',
  include_directories: include_directories('../imp'),
  link_with: common_lib,
  dependencies: vt_dep,
  install: false)

# No-network unit tests of the public API.  A request sent by mistake goes
# to 127.0.0.1:1 and must fail fast, never through a configured proxy.
unit_exe = executable('unit', 'unit.c', dependencies: vt_dep,
                      install: false)
test('unit', unit_exe, env: {'no_proxy': '*', 'NO_PROXY': '*'})

if fs.is_file('wire/meson.build')
  subdir('wire')
endif
