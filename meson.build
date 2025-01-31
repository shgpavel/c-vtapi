project('c-vtapi',
        'c',
        version: '0.1.0',
        license: 'Apache 2.0',
        default_options: [
          'c_std=c23',
          'debug=false',
        ],
        meson_version: '>=0.43')

libcvtapi_version = '0.1.0'

cc = meson.get_compiler('c')

cflags = ['-Wall', '-Werror']

conf = configuration_data()
# conf.set('_GNU_SOURCE', true)
conf.set_quoted('PACKAGE',  meson.project_name())


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
  add_project_arguments(cc.get_supported_arguments(extra_cflags), language : 'c')

  conf.set('CVTAPI_DEBUG', 1)
endif


jansson_dep = dependency('jansson')
curl_dep = dependency('libcurl')

cvtapi_dep = declare_dependency(
  include_directories: include_directories('lib'),
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
      'lib/VtUrlDist.c'
    ],
    c_args: cflags,
    dependencies: [jansson_dep, curl_dep]
  )
)


executable('scan', 'imp/scan.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('ip', 'imp/ip.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('comments', 'imp/comments.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('domain_report', 'imp/domain_report.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('file_dist', 'imp/file_dist.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('search', 'imp/search.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('url', 'imp/url.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])

executable('url_dist', 'imp/url_dist.c',
           dependencies: [jansson_dep, cvtapi_dep, curl_dep])
