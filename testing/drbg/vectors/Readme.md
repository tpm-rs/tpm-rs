# NIST Test Vectors for SP 800-90Ar1 Hash DRBG

The script `get_vectors.sh` is designed to be executed from this directory,
rather than from the root. When run, it will fetch the latest test vectors
from NIST. Currently, we have test vectors stored offline. If you need refresh
them simply execute the script. It will update the `Hash_DRBG.txt` files in
the `no_reseed`, `pr_false`, and `pr_true` folders.
