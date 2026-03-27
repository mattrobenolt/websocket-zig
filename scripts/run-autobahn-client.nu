#!/usr/bin/env nu
use ./autobahn-env.nu [config, run-stream-or-exit, setup-env]

def suite-profile [name: string] {
    match $name {
        "fast" => {
            {
                name: "fast"
                exclude_cases: ["9.*", "12.*", "13.*"]
            }
        }
        "full" => {
            {
                name: "full"
                exclude_cases: []
            }
        }
        _ => {
            print --stderr $"ERROR: unknown Autobahn profile: ($name)"
            print --stderr "Expected one of: fast, full"
            exit 1
        }
    }
}

def report-summary [reports_dir: path] {
    let index_path = [$reports_dir, "index.json"] | path join
    if (not ($index_path | path exists)) {
        print --stderr $"ERROR: missing Autobahn summary at ($index_path)"
        exit 1
    }
    let allowed_behaviors = ["OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED"]
    let results = (open $index_path)
    let summaries = ($results | transpose agent cases | each {|entry|
            let case_rows = ($entry.cases | transpose case_id data)
            let failed = (
                $case_rows
                | each {|case|
                    let behavior = ($case.data.behavior | default "")
                    if not ($allowed_behaviors | any {|allowed| $allowed == $behavior }) {
                        $case
                    }
                }
                | compact
                | sort-by case_id
            )

            {
                agent: $entry.agent
                total: ($case_rows | length)
                failed: $failed
            }
        })
    $summaries | each {|summary|
        let passed = ($summary.total - ($summary.failed | length))
        print $"($summary.agent): ($passed)/($summary.total) passed"

        if (($summary.failed | length) > 0) {
            $summary.failed
            | first 20
            | each {|case| print $"  FAIL ($case.case_id): ($case.data.behavior)"}

            if (($summary.failed | length) > 20) {
                print $"  ... and ((($summary.failed | length) - 20)) more"
            }
        }
    }
    if ($summaries | any {|summary| ($summary.failed | length) > 0 }) { exit 1 }
}

def main [
    client_bin: path
    server_port: int = 9001
    agent_name: string = echo-client
    profile_name: string = fast
] {
    setup-env
    if (not ($client_bin | path exists)) {
        print --stderr $"ERROR: client not found at ($client_bin)"
        exit 1
    }

    let cfg = (config)
    let profile = (suite-profile $profile_name)
    let host_ip = "127.0.0.1"
    let reports_dir = [$cfg.project_dir, "test", "autobahn", "reports", "clients"] | path join
    let wstest_script = [
        $cfg.script_dir
        "wstest-native.nu"
    ] | path join
    let autobahn_config = (^mktemp | str trim)
    {
        url: $"ws://($host_ip):($server_port)"
        outdir: $reports_dir
        cases: ["*"]
        exclude-cases: $profile.exclude_cases
        options: {failByDrop: false}
    } | to json --raw | save --force $autobahn_config

    rm -rf $reports_dir
    mkdir $reports_dir

    print $"Starting fuzzingserver on ($host_ip):($server_port)..."
    let wstest_job = (job spawn { run-stream-or-exit timeout "900" nu $wstest_script "-m" "fuzzingserver" "-s" $autobahn_config })
    try {
        sleep 2sec
        if ((job list | where id == $wstest_job | length) == 0) {
            print --stderr "ERROR: fuzzingserver failed to start"
            exit 1
        }
        print $"Running ($agent_name) against fuzzingserver at ws://($host_ip):($server_port)..."
        run-stream-or-exit $client_bin ($server_port | into string) $agent_name
        print ""
        print $"Results: ($reports_dir)/index.html"
        print ""
        report-summary $reports_dir
    } finally {
        try { job kill $wstest_job } catch { }
        rm -f $autobahn_config
    }
}
