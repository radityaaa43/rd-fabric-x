# fxconfig (fabric-x tools v1.0.1, pinned commit a00b9ef8) for the in-namespace S14 signing Jobs. Static binary built by .github/workflows/tools-image.yml; context is bin/.
# Base pinned by digest: the same one as panurus-itest/k8s/Dockerfile (the key-scan allow-list names it).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN useradd -u 10001 -m -d /home/tools tools
COPY fxconfig /usr/local/bin/fxconfig
USER 10001
ENV HOME=/home/tools
