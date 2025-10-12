#!/bin/bash

cat ./.example-smpc-server-gamma-key.txt | ../target/release/welsib-smpc-server --key=smpc-server-example.key --config=smpc.conf --pub --concurrency=4
