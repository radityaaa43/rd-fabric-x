# Runs the RD/DFABI integration test against a pinned Panurus checkout.
# Needs: docker, Go (version in Panurus go.mod) on PATH, network access.
PANURUS_TAG ?= v0.24.0
WORK        ?= $(CURDIR)/.work
SRC         ?= $(WORK)/panurus
PKG         := $(SRC)/integration/token/fungible/rdbi
GOBIN_DIR   ?= $(HOME)/go/bin

.PHONY: prepare test clean

# one-off: checkout, dev tools, fabric/fabric-x binaries, docker images (same steps as Panurus CI)
prepare:
	[ -d $(SRC) ] || git clone --depth 1 --branch $(PANURUS_TAG) https://github.com/LFDT-Panurus/panurus.git $(SRC)
	cd $(SRC) && make install-tools && make download-fabric fxconfig configtxgen testing-docker-images fabricx-docker-images

test:
	mkdir -p $(PKG) && cp rdbi/*.go $(PKG)/
	cd $(PKG) && PATH=$(GOBIN_DIR):$$PATH FAB_BINS=$(SRC)/../fabric/bin ginkgo --keep-going .

clean:
	rm -rf $(WORK) $(PKG)
