# fsc-reenroll: fabric-ca-client v1.5.22 (release tarball, sha256 checked by the workflow) + the static Go helper, for the in-namespace FSC identity re-issue Jobs (fabricx S13 SAN fix).
# Base pinned by digest: the same one as panurus-itest/k8s/Dockerfile and multiorg/ceremony/Dockerfile (the key-scan allow-list names it). Context is bin/ (the two binaries). No shell tooling beyond the base.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN useradd -u 10001 -m -d /home/reenroll reenroll
COPY fabric-ca-client /usr/local/bin/fabric-ca-client
COPY fsc-reenroll /usr/local/bin/fsc-reenroll
USER 10001
ENV HOME=/home/reenroll
