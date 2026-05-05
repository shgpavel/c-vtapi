project(
    'c-vtapi',
    'c',
    version: '0.1.0',
    license: 'Apache-2.0',
    default_options: ['c_std=c23,c2x', 'debug=false'],
    meson_version: '>=1.3.0')

cc = meson.get_compiler('c')
fs = import('fs')

if cc.has_argument('-std=c23')
    message('C standard: c23')
else
    message('C standard: c2x fallback')
endif

cflags = ['-Wall', '-Werror']
curl_dep = dependency('libcurl')
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

v3_examples = ['comments', 'domain_report', 'file_dist', 'ip', 'scan',
               'search', 'url', 'url_dist']

foreach example : v3_examples
    executable(
        'vt3_' + example,
        'users/v3/' + example + '.c',
        c_args: cflags,
        dependencies: [cvtapi_v3_dep],
    )
endforeach

if get_option('tests') and fs.is_dir('lib/v3/tests')
    v3_test_source_list = run_command(
        'find', 'lib/v3/tests', '-maxdepth', '1', '-type', 'f', '-name',
        '*.c', check: true).stdout().strip()

    if v3_test_source_list != ''
        network_tests_enabled = run_command(
            'sh', '-c', 'test "${VTAPI_RUN_NETWORK_TESTS:-0}" = "1"',
            check: false).returncode() == 0

        foreach test_source : v3_test_source_list.split('\n')
            test_name = fs.stem(test_source)
            is_network_test = test_name.contains('network')

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
endif
