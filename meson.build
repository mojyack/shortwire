project('p2p-vpn', 'cpp', version: '1.0.0', default_options : ['warning_level=3', 'werror=false', 'cpp_std=c++20'])

subdir('src/p2p')

tcp_vpn_files = files(
  'src/tcp-vpn.cpp',
  'src/common.cpp',
)

ws_vpn_files = files(
  'src/ws-vpn.cpp',
  'src/common.cpp',
) + p2p_client_common_files
ws_vpn_deps = p2p_client_common_deps

p2p_vpn_files = files(
  'src/p2p-vpn.cpp',
  'src/common.cpp',
  'src/args.cpp',
) + p2p_client_ice_files
p2p_vpn_deps = p2p_client_ice_deps

executable('tcp-vpn', tcp_vpn_files,
  install : true)

executable('ws-vpn', ws_vpn_files,
  dependencies : ws_vpn_deps,
  install : true)

executable('p2p-vpn', p2p_vpn_files,
  dependencies : p2p_vpn_deps,
  install : true)
