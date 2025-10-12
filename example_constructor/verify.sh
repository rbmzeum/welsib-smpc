#/bin/bash

cat ./certificate.txt | ./bin/welsib-smpc-verifier --config=smpc.conf
