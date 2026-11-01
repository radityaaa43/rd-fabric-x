# RD/DFABI on Fabric-X with Panurus (ZKAT-DLOG): local integration test and live deployment.
# Needs: docker (test only), Go on PATH (version in Panurus go.mod), network access, kubectl+KUBECONFIG (live only).
PANURUS_TAG ?= v0.24.0
WORK        ?= $(CURDIR)/.work
SRC         ?= $(WORK)/panurus
PKG         := $(SRC)/integration/token/fungible/rdbi
GOBIN_DIR   ?= $(HOME)/go/bin
RDBI_HOME   ?= $(HOME)/.fabricx-token
FSC_PATCHED := $(WORK)/fsc

.PHONY: prepare test clean fsc-patch panurus-patch live-build live-gen live-enroll live-assemble live-start live-stop live-pp live-scenario live-committers live-report live-reconcile

# one-off: checkout, dev tools, fabric/fabric-x binaries, docker images (same steps as Panurus CI)
prepare:
	[ -d $(SRC) ] || git clone --depth 1 --branch $(PANURUS_TAG) https://github.com/LFDT-Panurus/panurus.git $(SRC)
	cd $(SRC)/integration && go get gopkg.in/yaml.v3@v3.0.1 # the driver parses client-config.yaml
	cd $(SRC) && make install-tools && make download-fabric fxconfig configtxgen testing-docker-images fabricx-docker-images

# local test: starts its own Fabric-X in docker, unpatched upstream code
test:
	mkdir -p $(PKG) && cp -r rdbi/. $(PKG)/
	cd $(PKG) && PATH=$(GOBIN_DIR):$$PATH FAB_BINS=$(SRC)/../fabric/bin ginkgo --keep-going .

# --- live deployment: token nodes on this host against an EXISTING Fabric-X network ----------------
# The FSC fabricx driver (v0.24.0) always sends cached certificate IDs, which only verify when the signer
# certificates are listed in the channel config (known_certs). On a network that does not list them we
# send the full certificate instead (supported by the committer); see patches/ and README.md.
fsc-patch:
	cd $(SRC)/integration && D=$$(go list -m -f '{{.Dir}}' github.com/hyperledger-labs/fabric-smart-client) && 	  rm -rf $(FSC_PATCHED) && cp -r $$D $(FSC_PATCHED) && chmod -R u+w $(FSC_PATCHED) && 	  cd $(FSC_PATCHED) && patch -p1 < $(CURDIR)/patches/fsc-full-certificate.patch && 	  cd $(SRC)/integration && go mod edit -replace github.com/hyperledger-labs/fabric-smart-client=$(FSC_PATCHED)

# Panurus patches (see README.md): configurable holding limit in the demo views, endorser failover for
# namespace policies such as 3-of-4, sequential remote signature requests (DvP with multi-token counterparties),
# the issuer keeps audit tokens when the public parameters list no auditor (reports to BI)
panurus-patch:
	cd $(SRC) && for p in $(CURDIR)/patches/panurus-*.patch; do \
	  (patch -p1 -N --dry-run < $$p >/dev/null && patch -p1 -N < $$p || echo "already applied: $$p"); done

live-build:
	mkdir -p $(PKG) $(RDBI_HOME)/bin && cp -r rdbi/. $(PKG)/
	cd $(SRC)/integration && go build -o $(RDBI_HOME)/bin/rdbi-node ./token/fungible/rdbi/cmd/node && 	  go build -o $(RDBI_HOME)/bin/rdbi-driver ./token/fungible/rdbi/cmd/driver

# generate crypto, wallets and public parameters with Panurus's own generators (no process started)
live-gen:
	mkdir -p $(PKG) && cp -r rdbi/. $(PKG)/
	cd $(PKG) && PATH=$(GOBIN_DIR):$$PATH FAB_BINS=$(SRC)/../fabric/bin RDBI_GENERATE=$(RDBI_HOME)/livegen go test -run TestGenerate -count=1 .

# one ledger identity per node at its organisation's CA (needs FABRIC_CA_CLIENT=<binary>, KUBECONFIG)
live-enroll:
	python3 -I scripts/enroll_ids.py

live-assemble:
	python3 -I scripts/assemble.py

live-start:
	./scripts/run.sh start
live-stop:
	./scripts/run.sh stop

# once per namespace: put the public parameters on the ledger; then run the scenario
live-pp:
	$(RDBI_HOME)/bin/rdbi-driver setup-pp
live-scenario:
	$(RDBI_HOME)/bin/rdbi-driver scenario

# one committer per bank on this host (../multiorg/committer); needs live-enroll and the forward shim (live-start)
live-committers:
	../multiorg/committer/committer.sh up

# reports to BI (rdbi/report): catch up after BI was offline, then check the ledger against BI's records
live-report:
	$(RDBI_HOME)/bin/rdbi-driver report
live-reconcile:
	python3 -I scripts/reconcile.py

clean:
	rm -rf $(WORK) $(PKG)
