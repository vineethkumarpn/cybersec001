OHM Shri Maha Ganapathaye Namah.
--------------------------------
This is my first project on cybersec code to explore weakness in the virtualization and cloud world.
<H1>Scenario one</H1>
Automated system initialization on public cloud instances like cloud-init can be explored more to gain access access to the undelying host system.

## Safe artifact inspection

`gethost.c` provides a host-side SHA-256 verifier for files placed in
`/var/lib/vm-artifacts/incoming`. It accepts only a basename, opens the file
without following symlinks, and limits input to 64 MiB. The expected digest
must come from a trusted channel separate from the staged file.

The program does not use cloud-init, copy files, or execute the inspected
artifact.

Build on Linux with OpenSSL development headers installed:

```sh
cc -Wall -Wextra -Wpedantic -O2 gethost.c -o gethost -lcrypto
```

Run as a host-side operator after placing an artifact in the incoming
directory. Replace `TRUSTED_SHA256_HEX` with the 64-character digest obtained
through a trusted channel:

```sh
./gethost artifact.bin TRUSTED_SHA256_HEX
```