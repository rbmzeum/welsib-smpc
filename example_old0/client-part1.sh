#!/bin/bash

cat ./.example-smpc-client-part1-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-part1-example.key --config=smpc.conf --concurrency=4 --value=55
