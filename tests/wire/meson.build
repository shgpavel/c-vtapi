# Wire-level regression suite (see README.md).  Included from
# tests/meson.build, which provides vt_tools (tool name -> executable) and
# vtprobe_exe.  Scenarios are generated into the build directory at test
# time; every mock listens on a free port, so this runs alongside anything.
wire_python = find_program('python3')

wire_args = [meson.current_source_dir() / 'run.py',
             '--workdir', meson.current_build_dir() / 'wire-work',
             '--probe', vtprobe_exe.full_path(),
             '--quiet']
wire_deps = [vtprobe_exe]
foreach name, exe : vt_tools
  wire_args += ['--tool', name + '=' + exe.full_path()]
  wire_deps += exe
endforeach

test('wire', wire_python,
     args: wire_args,
     depends: wire_deps,
     timeout: 900,
     suite: 'wire')
