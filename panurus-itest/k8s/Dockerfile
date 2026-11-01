# rdbi-node (FSC/Panurus node) and rdbi-driver, built by `make live-build`; context is $(RDBI_HOME)/bin.
# The binaries need glibc >= 2.34 (bookworm has 2.36). Configs and keys are mounted at $HOME/.fabricx-token.
FROM debian:bookworm-slim
RUN useradd -u 10001 -m -d /home/rdbi rdbi
COPY rdbi-node rdbi-driver /usr/local/bin/
USER 10001
ENV HOME=/home/rdbi
