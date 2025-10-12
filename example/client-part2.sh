#!/bin/bash

cat .example-smpc-client-part2-password.txt | ../target/release/welsib-smpc-client --key=smpc-client-part2-example-key.pem --config=smpc.conf --concurrency=4 --value=value-client-part2.txt.aggc > part2.txt
