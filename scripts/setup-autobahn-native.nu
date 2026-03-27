#!/usr/bin/env nu
use ./autobahn-env.nu [
    autobahn-import-check
    config
    project-dir
    run-capture
    run-or-exit
    setup-env
]
def lockfile [] {
    [
        (project-dir)
        "test"
        "autobahn"
        "requirements.txt"
    ] | path join
}
def source-tree-dir [cfg: record] {
    [
        $cfg.autobahn_checkout_dir
        "autobahntestsuite"
    ] | path join
}
def install-fingerprint [lockfile_path: path, cfg: record] { $"lock_sha256=(open --raw $lockfile_path | hash sha256)\nsource_dir=($cfg.autobahn_checkout_dir)\n" }
def bootstrap-pip [] {
    if ((run-capture pypy "-m" "pip" "--version").exit_code == 0) { return }
    print $"Bootstrapping pip into ($env.AUTOBAHN_PYTHONUSERBASE)"
    run-or-exit pypy "-m" "ensurepip" "--user"
}
def install-locked-requirement [lockfile_path: path, pattern: string] {
    let requirement_lock = (^mktemp | str trim)
    let matches = (
        open --raw $lockfile_path | lines | each {|line| if $line =~ $pattern { $line } } | compact
    )
    if ($matches | is-empty) {
        print --stderr $"ERROR: missing pinned requirement matching /($pattern)/ in ($lockfile_path)"
        rm -f $requirement_lock
        exit 1
    }
    ($matches | append "" | str join "\n") | save --force $requirement_lock
    try { run-or-exit pypy "-m" "pip" "install" "--user" "--no-build-isolation" "--require-hashes" "--no-binary=:all:" "--no-deps" "-r" $requirement_lock } finally { rm -f $requirement_lock }
}
def install-bootstrap-dependencies [lockfile_path: path] {
    install-locked-requirement $lockfile_path '^setuptools=='
    install-locked-requirement $lockfile_path '^wheel=='
    install-locked-requirement $lockfile_path '^pip=='
    install-locked-requirement $lockfile_path '^typing=='
    install-locked-requirement $lockfile_path '^incremental=='
}
def autobahn-install-is-current [lockfile_path: path, cfg: record] {
    if (not (autobahn-import-check)) { return false }
    if (not ($cfg.autobahn_stamp_file | path exists)) { return false }
    (open --raw $cfg.autobahn_stamp_file) == (install-fingerprint $lockfile_path $cfg)
}
def write-install-stamp [lockfile_path: path, cfg: record] {
    install-fingerprint $lockfile_path $cfg | save --force $cfg.autobahn_stamp_file
}
def reset-runtime-env [cfg: record] {
    rm -rf $cfg.autobahn_pythonuserbase
    rm -f $cfg.autobahn_stamp_file
    mkdir $cfg.autobahn_home
}
def check-inputs [lockfile_path: path, cfg: record] {
    if (not ($lockfile_path | path exists)) {
        print --stderr $"ERROR: missing lockfile at ($lockfile_path)"
        print --stderr "Run: just autobahn-lock"
        exit 1
    }
    if (not ((source-tree-dir $cfg) | path exists)) {
        print --stderr $"ERROR: missing Autobahn source at ($cfg.autobahn_checkout_dir)"
        exit 1
    }
}
def install-autobahn [lockfile_path: path, cfg: record] {
    print $"Installing Autobahn TestSuite into ($cfg.autobahn_pythonuserbase)"
    reset-runtime-env $cfg
    bootstrap-pip
    install-bootstrap-dependencies $lockfile_path
    run-or-exit pypy "-m" "pip" "install" "--user" "--no-build-isolation" "--require-hashes" "--no-binary=:all:" "-r" $lockfile_path
    let source_stage_root = (^mktemp -d | str trim)
    let source_stage_dir = [$source_stage_root, "autobahntestsuite"] | path join
    try {
        run-or-exit cp "-R" (source-tree-dir $cfg) $source_stage_dir
        run-or-exit chmod "-R" "u+w" $source_stage_dir
        run-or-exit pypy "-m" "pip" "install" "--user" "--no-build-isolation" "--no-deps" $source_stage_dir
    } finally { rm -rf $source_stage_root }
    write-install-stamp $lockfile_path $cfg
}
def main [] {
    setup-env
    let cfg = (config)
    let lockfile_path = (lockfile)
    check-inputs $lockfile_path $cfg
    if (autobahn-install-is-current $lockfile_path $cfg) { print $"Autobahn TestSuite is already importable from ($cfg.autobahn_site_packages)" } else { install-autobahn $lockfile_path $cfg }
    print ""
    print "Autobahn TestSuite ready"
    print $"  source: ($cfg.autobahn_checkout_dir)"
    print $"  site-packages: ($cfg.autobahn_site_packages)"
    print ""
    run-or-exit pypy "-m" "autobahntestsuite.wstest" "--autobahnversion" | ignore
}
