#!/bin/sh
rm no_reseed pr_false pr_true -rf
rm drbgtestvectors.zip  drbgvectors_no_reseed.zip  drbgvectors_pr_false.zip  drbgvectors_pr_true.zip -f
mkdir no_reseed pr_false pr_true
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
unzip drbgtestvectors.zip
unzip drbgvectors_no_reseed.zip Hash_DRBG.txt -d no_reseed
unzip drbgvectors_pr_false.zip Hash_DRBG.txt -d pr_false
unzip drbgvectors_pr_true.zip Hash_DRBG.txt -d pr_true
rm drbgtestvectors.zip  drbgvectors_no_reseed.zip  drbgvectors_pr_false.zip  drbgvectors_pr_true.zip -f
