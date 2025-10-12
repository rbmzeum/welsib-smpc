#!/bin/bash

cat ./.example-smpc-client-sum-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-sum-example.key --config=smpc.conf --sum --concurrency=4 --value=100
