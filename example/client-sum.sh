#!/bin/bash

cat .example-smpc-client-sum-password.txt | ../target/release/welsib-smpc-client --key=smpc-client-sum-example-key.pem --config=smpc.conf --concurrency=4 --value=value-client-sum.txt.aggc --sum > sum.txt
