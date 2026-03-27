#!/usr/bin/env nu
use ./autobahn-env.nu [autobahn-import-check, setup-env]
def --wrapped main [...args: string] {
    setup-env
    if (not (autobahn-import-check)) {
        print --stderr "Autobahn TestSuite is not installed yet."
        print --stderr "Run: just autobahn-setup"
        exit 1
    }
    let actual_args = if ($args | is-empty) { ["--help"] } else { $args }
    exec pypy "-u" "-m" "autobahntestsuite.wstest" ...$actual_args
}
