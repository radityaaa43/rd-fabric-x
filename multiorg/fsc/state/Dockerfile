# Stock sqlite3 CLI (Debian bookworm package, version pinned) for the FSC node-DB checks: read-only table/row counts and, after the analyst gate, the backup + removal of default.sqlite. No code of ours.
# Base pinned by digest: the same one as panurus-itest/k8s/Dockerfile (the key-scan allow-list names it). The other packages pulled as dependencies (readline, zlib, ...) are listed in the build summary (dpkg-query).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends sqlite3=3.40.1-2+deb12u2 libsqlite3-0=3.40.1-2+deb12u2 \
 && apt-get clean \
 && useradd -u 10001 -m -d /home/state state
USER 10001
ENV HOME=/home/state
