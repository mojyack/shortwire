project('p2p-vpn', 'cpp', version: '1.0.0', default_options : ['warning_level=3', 'werror=false', 'cpp_std=c++20'])

deps = [
]

tcp_vpn_files = files(
  'src/tcp-vpn.cpp',
  'src/common.cpp',
)

executable('tcp-vpn', tcp_vpn_files,
  install : true)
