def join-non-empty [values, separator: string] {
    $values | each {|value| $value | default "" | into string } | each {|value| if $value != "" { $value } } | compact | str join $separator
}
def prepend-path-entry [entry: path, current_path] {
    [$entry] | append ($current_path | default []) | flatten | each {|value| $value | into string } | uniq
}
def pkg-config-value [package: string, variable: string] {
    run-external pkg-config $"--variable=($variable)" $package | str trim
}
export def project-dir [] {
    $env.PWD | path expand
}
def script-dir [] {
    [
        (project-dir)
        "scripts"
    ] | path join
}
export def config [] {
    let root_dir = (project-dir)
    let scripts_dir = (script-dir)
    let autobahn_home = ($env | get --optional AUTOBAHN_HOME | default ([$root_dir, ".autobahn"] | path join))
    let autobahn_pythonuserbase = ($env | get --optional AUTOBAHN_PYTHONUSERBASE | default ([$autobahn_home, "pypy-user"] | path join))
    let autobahn_site_packages = ($env | get --optional AUTOBAHN_SITE_PACKAGES | default ([$autobahn_pythonuserbase, "lib", "pypy2.7", "site-packages"] | path join))
    let autobahn_bin_dir = ($env | get --optional AUTOBAHN_BIN_DIR | default ([$autobahn_pythonuserbase, "bin"] | path join))
    let autobahn_checkout_dir = ($env | get --optional AUTOBAHN_CHECKOUT_DIR | default ([$autobahn_home, "src", "autobahn-testsuite"] | path join))
    let autobahn_reports_dir = ($env | get --optional AUTOBAHN_REPORTS_DIR | default ([$root_dir, "test", "autobahn", "reports"] | path join))
    let autobahn_bootstrap_dir = ($env | get --optional AUTOBAHN_BOOTSTRAP_DIR | default ([$scripts_dir, "python-bootstrap"] | path join))
    let autobahn_stamp_file = ($env | get --optional AUTOBAHN_STAMP_FILE | default ([$autobahn_home, "install.stamp"] | path join))
    {
        project_dir: $root_dir
        script_dir: $scripts_dir
        autobahn_home: $autobahn_home
        autobahn_pythonuserbase: $autobahn_pythonuserbase
        autobahn_site_packages: $autobahn_site_packages
        autobahn_bin_dir: $autobahn_bin_dir
        autobahn_checkout_dir: $autobahn_checkout_dir
        autobahn_reports_dir: $autobahn_reports_dir
        autobahn_bootstrap_dir: $autobahn_bootstrap_dir
        autobahn_stamp_file: $autobahn_stamp_file
    }
}
export def report-command-result [result: record] {
    if (($result.stdout | default "") != "") { print --raw $result.stdout }
    if (($result.stderr | default "") != "") { print --stderr --raw $result.stderr }
}
export def run-capture [...command] {
    run-external ...$command | complete
}
export def run-or-exit [...command] {
    let result = (run-capture ...$command)
    report-command-result $result
    if $result.exit_code != 0 { exit $result.exit_code }
    $result
}
export def run-stream-or-exit [...command] {
    run-external ...$command
    if $env.LAST_EXIT_CODE != 0 { exit $env.LAST_EXIT_CODE }
}
export def --env setup-env [] {
    let cfg = (config)
    mkdir $cfg.autobahn_home
    mkdir $cfg.autobahn_reports_dir
    load-env {
        AUTOBAHN_HOME: $cfg.autobahn_home
        AUTOBAHN_PYTHONUSERBASE: $cfg.autobahn_pythonuserbase
        AUTOBAHN_SITE_PACKAGES: $cfg.autobahn_site_packages
        AUTOBAHN_BIN_DIR: $cfg.autobahn_bin_dir
        AUTOBAHN_CHECKOUT_DIR: $cfg.autobahn_checkout_dir
        AUTOBAHN_REPORTS_DIR: $cfg.autobahn_reports_dir
        AUTOBAHN_BOOTSTRAP_DIR: $cfg.autobahn_bootstrap_dir
        AUTOBAHN_STAMP_FILE: $cfg.autobahn_stamp_file
        PYTHONUSERBASE: $cfg.autobahn_pythonuserbase
        PIP_NO_BUILD_ISOLATION: "1"
        PATH: (prepend-path-entry $cfg.autobahn_bin_dir ($env.PATH?))
        PYTHONPATH: (join-non-empty [$cfg.autobahn_bootstrap_dir ($env.PYTHONPATH?)] (char esep))
    }
    let openssl_include_dir = (pkg-config-value openssl includedir)
    let openssl_lib_dir = (pkg-config-value openssl libdir)
    load-env {
        OPENSSL_INCLUDE_DIR: $openssl_include_dir
        OPENSSL_LIB_DIR: $openssl_lib_dir
        OPENSSL_DIR: ($openssl_lib_dir | path dirname)
        CFLAGS: (join-non-empty [($env.CFLAGS?) $"-I($openssl_include_dir)"] " ")
        CPPFLAGS: (join-non-empty [($env.CPPFLAGS?) $"-I($openssl_include_dir)"] " ")
        LDFLAGS: (join-non-empty [($env.LDFLAGS?) $"-L($openssl_lib_dir)"] " ")
        C_INCLUDE_PATH: (join-non-empty [($env.C_INCLUDE_PATH?) $openssl_include_dir] (char esep))
        LIBRARY_PATH: (join-non-empty [($env.LIBRARY_PATH?) $openssl_lib_dir] (char esep))
    }
    let libffi_include_dir = (pkg-config-value libffi includedir)
    let libffi_lib_dir = (pkg-config-value libffi libdir)
    load-env {
        LIBFFI_INCLUDEDIR: $libffi_include_dir
        LIBFFI_LIBDIR: $libffi_lib_dir
        LIBFFI_DIR: ($libffi_lib_dir | path dirname)
        CFLAGS: (join-non-empty [($env.CFLAGS?) $"-I($libffi_include_dir)"] " ")
        CPPFLAGS: (join-non-empty [($env.CPPFLAGS?) $"-I($libffi_include_dir)"] " ")
        LDFLAGS: (join-non-empty [($env.LDFLAGS?) $"-L($libffi_lib_dir)"] " ")
        C_INCLUDE_PATH: (join-non-empty [($env.C_INCLUDE_PATH?) $libffi_include_dir] (char esep))
        LIBRARY_PATH: (join-non-empty [($env.LIBRARY_PATH?) $libffi_lib_dir] (char esep))
    }
}
export def autobahn-import-check [] { (run-capture pypy "-m" "autobahntestsuite.wstest" "--autobahnversion").exit_code == 0 }
