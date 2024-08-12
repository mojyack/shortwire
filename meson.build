project('shortwire', 'cpp', version: '1.0.0', default_options : ['warning_level=3', 'werror=false', 'cpp_std=c++20'])
add_project_arguments('-Wno-missing-field-initializers', language: 'cpp')

subdir('src/p2p')
subdir('src/crypto')

executable('shortwired', files(
    'src/shortwired.cpp',
    'src/common.cpp',
    'src/args.cpp',
    'src/crypto/cipher.cpp',
    'src/crypto/aes.cpp',
  ) + p2p_client_ice_files,
  dependencies : p2p_client_ice_deps + crypto_utils_deps,
  install : true)
