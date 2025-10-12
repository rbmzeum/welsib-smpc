#/bin/bash

cat ./certificate.txt | ../target/release/welsib-smpc-verifier --config=smpc.conf

