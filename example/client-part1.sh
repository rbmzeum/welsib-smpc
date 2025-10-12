#!/bin/bash

cat .example-smpc-client-part1-password.txt | ../target/release/welsib-smpc-client --key=smpc-client-part1-example-key.pem --config=smpc.conf --concurrency=4 --value=value-client-part1.txt.aggc > part1.txt
