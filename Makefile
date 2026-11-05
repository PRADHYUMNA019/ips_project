# Makefile — ips_project build, test, and evaluation targets.
#
# Usage:
#   make test          Run unit tests (no root needed)
#   make test-all      Run ALL tests including root-required ones
#   make topo          Create the network topology (needs sudo)
#   make topo-down     Tear down the topology
#   make certs         Generate TLS certificates
#   make data-audit    Audit datasets and regenerate DATA_CARD.md
#   make features      Extract features from testbed captures
#   make train         Train models
#   make eval-offline  Run offline evaluation
#   make eval-system   Run system evaluation (needs sudo)
#   make reproduce     Reproduce all results from raw data
#   make clean         Remove build artifacts

.PHONY: test test-all topo topo-down certs data-audit features train \
        eval-offline eval-system reproduce clean

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
test:
	python -m pytest tests/ -v -m "not root and not slow" --tb=short

test-all:
	sudo python -m pytest tests/ -v --tb=short

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------
topo:
	sudo bash scripts/topology.sh create

topo-down:
	sudo bash scripts/topology.sh teardown

certs:
	bash scripts/gen_certs.sh

# ---------------------------------------------------------------------------
# Data pipeline (stubs — filled in WP2–WP5)
# ---------------------------------------------------------------------------
data-audit:
	python datasets/audit_pcap.py datasets/raw --out docs/DATA_CARD.md

features:
	@echo "Extracting features from pcaps..."
	python -c "import os, glob; [os.system(f'python ips/offline/pcap_to_flows.py {p} --out {p}.csv') for p in glob.glob('results/**/*.pcap', recursive=True)]"

DATA ?= results/smoke/smoke_train_sess.csv
TEST_DATA ?= results/smoke/smoke_quick_test.csv

train:
	python ips/models/train.py --data $(DATA)

eval-offline:
	python ips/models/eval_offline.py --test-data $(TEST_DATA) --card models/model_card.json

eval-system:
	python ips/eval/harness.py

reproduce:
	python ips/eval/reproduce.py

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache build dist *.egg-info

