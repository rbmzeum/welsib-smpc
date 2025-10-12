#!/bin/bash

cat .example-smpc-server-password.txt | ../target/release/welsib-smpc-server --key=smpc-server-example-key.pem --config=smpc.conf --concurrency=4 > certificate.txt
