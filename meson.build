project(
    'c-vtapi',
    'c',
    version: '0.1.0',
    license: 'Apache 2.0',
    default_options: ['c_std=c23,c2x', 'debug=false'],
    meson_version: '>=1.3.0',
)

libcvtapi_version = '0.1.0'

cc = meson.get_compiler('c')
fs = import('fs')

if cc.has_argument('-std=c23')
    message('C standard: c23')
else
    message('C standard: c2x fallback')
endif

cflags = ['-Wall', '-Werror']

conf = configuration_data()
conf.set('_POSIX_C_SOURCE', true)
conf.set_quoted('PACKAGE', meson.project_name())

if get_option('debug')
    extra_cflags = [
        '-g3',
        '-pedantic',
        '-Wcast-align',
        '-Wclobbered',
        '-Wempty-body',
        '-Wfloat-equal',
        '-Wformat-nonliteral',
        '-Wformat-security',
        '-Wignored-qualifiers',
        '-Wimplicit-fallthrough',
        '-Winit-self',
        '-Wlogical-op',
        '-Wmissing-declarations',
        '-Wmissing-field-initializers',
        '-Wmissing-parameter-type',
        '-Wmissing-prototypes',
        '-Wold-style-declaration',
        '-Woverride-init',
        '-Wpointer-arith',
        '-Wredundant-decls',
        '-Wshadow',
        '-Wsign-compare',
        '-Wstrict-aliasing',
        '-Wstrict-overflow=5',
        '-Wstrict-prototypes',
        '-Wtype-limits',
        '-Wuninitialized',
        '-Wunused-but-set-parameter',
        '-Wunused-parameter',
        '-Wunused-result',
        '-Wwrite-strings',
    ]
    add_project_arguments(
        cc.get_supported_arguments(extra_cflags),
        language: 'c',
    )

    conf.set('CVTAPI_DEBUG', 1)
endif

curl_dep = dependency('libcurl')

if get_option('vt_v3')
    yyjson_dep = dependency('yyjson', fallback: ['yyjson', 'yyjson_dep'])
    vt_include_dir = include_directories('include')

    subdir('lib/v3')

    cvtapi_v3_lib = static_library(
        'cvtapi_v3',
        sources: v3_sources,
        c_args: cflags,
        include_directories: vt_include_dir,
        dependencies: [curl_dep, yyjson_dep],
        install: true,
    )

    cvtapi_v3_dep = declare_dependency(
        include_directories: vt_include_dir,
        link_with: cvtapi_v3_lib,
        dependencies: [curl_dep, yyjson_dep],
    )

    install_subdir('include/vt', install_dir: get_option('includedir'))

    v3_examples = [
        'comments',
        'domain_report',
        'file_dist',
        'ip',
        'scan',
        'search',
        'url',
        'url_dist',
    ]

    foreach example : v3_examples
        executable(
            'vt3_' + example,
            'users/v3/' + example + '.c',
            c_args: cflags,
            dependencies: [cvtapi_v3_dep],
        )
    endforeach

    if get_option('tests')
        if fs.is_dir('lib/v3/tests')
            v3_test_source_list = run_command(
                'find',
                'lib/v3/tests',
                '-maxdepth',
                '1',
                '-type',
                'f',
                '-name',
                '*.c',
                check: true,
            ).stdout().strip()

            if v3_test_source_list != ''
                network_tests_enabled = run_command(
                    'sh',
                    '-c',
                    'test "${VTAPI_RUN_NETWORK_TESTS:-0}" = "1"',
                    check: false,
                ).returncode() == 0

                foreach test_source : v3_test_source_list.split('\n')
                    test_name = fs.stem(test_source)
                    is_network_test = (
                        test_name.contains('network') or
                        test_name.contains('smoke')
                    )

                    if not is_network_test or network_tests_enabled
                        test_exe = executable(
                            'vt3_test_' + test_name,
                            test_source,
                            c_args: cflags,
                            dependencies: [cvtapi_v3_dep],
                        )
                        test('vt3_' + test_name, test_exe)
                    endif
                endforeach
            endif
        else
            message('No lib/v3/tests directory found; skipping v3 tests.')
        endif
    endif
endif

if get_option('vt_v2_legacy')
    jansson_dep = dependency('jansson')
    legacy_include_dir = include_directories(
        'include',
        get_option('include-dir'),
    )

    cvtapi_dep = declare_dependency(
        include_directories: legacy_include_dir,
        link_with: static_library(
            'cvtapi',
            sources: [
                'lib/VtObject.c',
                'lib/VtApiPage.c',
                'lib/VtComments.c',
                'lib/VtDebug.c',
                'lib/VtDomain.c',
                'lib/VtFile.c',
                'lib/VtFileDist.c',
                'lib/VtIpAddr.c',
                'lib/VtResponse.c',
                'lib/VtUrl.c',
                'lib/VtUrlDist.c',
            ],
            c_args: cflags,
            include_directories: legacy_include_dir,
            dependencies: [jansson_dep, curl_dep],
            override_options: ['c_std=c99'],
        ),
    )

    legacy_examples = [
        'comments',
        'domain_report',
        'file_dist',
        'ip',
        'scan',
        'search',
        'url',
        'url_dist',
    ]

    foreach example : legacy_examples
        executable(
            example,
            'users/' + example + '.c',
            dependencies: [jansson_dep, cvtapi_dep, curl_dep],
            override_options: ['c_std=c99'],
        )
    endforeach
endif
