#!/bin/bash

cat ./.example-smpc-client-part2-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-part2-example.key --config=smpc.conf --concurrency=4 --value=45
