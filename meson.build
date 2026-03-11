project('rz-nd100', 'c',
    version: '1.0.3',
    license: 'LGPL-3.0-only',
    default_options: ['c_std=c11', 'warning_level=2'],
)

# Rizin 0.8.0 merged rz_asm into rz_arch; rz_core pulls everything in
rz_core_dep = dependency('rz_core')

# Get plugin install directory from pkg-config
plugindir = rz_core_dep.get_variable(pkgconfig: 'plugindir')
plugins_dir = get_option('prefix') / plugindir

shared_library('asm_nd100',
    ['src/rz_asm_nd100.c', 'src/nd100_disasm.c', 'src/moncalls.c', 'src/iodevs.c'],
    dependencies: [rz_core_dep],
    install: true,
    install_dir: plugins_dir,
    name_prefix: '',
)

shared_library('analysis_nd100',
    ['src/rz_analysis_nd100.c', 'src/nd100_disasm.c', 'src/moncalls.c'],
    dependencies: [rz_core_dep],
    install: true,
    install_dir: plugins_dir,
    name_prefix: '',
)

shared_library('bin_bpun',
    ['src/rz_bin_bpun.c'],
    dependencies: [rz_core_dep],
    install: true,
    install_dir: plugins_dir,
    name_prefix: '',
)

shared_library('bin_aout16',
    ['src/rz_bin_aout16.c'],
    dependencies: [rz_core_dep],
    install: true,
    install_dir: plugins_dir,
    name_prefix: '',
)

shared_library('parse_nd100',
    ['src/rz_parse_nd100.c'],
    dependencies: [rz_core_dep],
    install: true,
    install_dir: plugins_dir,
    name_prefix: '',
)
