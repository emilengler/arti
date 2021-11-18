#!/bin/bash
set -xe

cd "$(git rev-parse --show-toplevel)"

source tests/chutney/arti.run

kill -s INT "$pid"; 
# wait $pid, but $pid was started by a different process
tail --pid="$pid" -f /dev/null


./chutney/chutney stop "$target"

source tests/chutney/arti.run
if [ "$result" != 0 ]; then
	exit "$result"
fi

if [ "${COVERAGE}" == 1 ]; then
	grcov coverage_meta/ --binary-path target/debug/ -s crates/ -t html --branch --ignore-not-existing -o coverage/
fi
