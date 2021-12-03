#!/bin/sh

path=$(dirname $0)
"$path/with_coverage.sh" cargo test --all-features
