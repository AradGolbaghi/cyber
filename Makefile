# Hacker-Life Lab convenience Makefile
# Usage:
#   make install             # create venv + install deps
#   make run                 # run main.py (uses venv python if available)
#   make scan HOST=127.0.0.1 PORTS=1-1024 TIMEOUT=0.8 OUT=scan.json
#   make clean               # remove .venv
#   make report-dir          # show reports dir
#   make help                # print targets

# -------- Python + venv detection --------
# On Windows, $(OS) is "Windows_NT"
ifeq ($(OS),Windows_NT)
  PY ?= py -3
  VENV_BIN := .venv/Scripts
  ACTIVATE_HINT := .venv\Scripts\activate
else
  PY ?= python3
  VENV_BIN := .venv/bin
  ACTIVATE_HINT := source .venv/bin/activate
endif

PIP        ?= $(PY) -m pip
VENV        = .venv
VENVPY      = $(VENV_BIN)/python
VENVPIP     = $(VENV_BIN)/pip

.DEFAULT_GOAL := help

.PHONY: help venv install install-user run menu scan clean report-dir

help:
	@echo "Targets:"
	@echo "  make install        Create venv and install requirements"
	@echo "  make install-user   pip install --user requirements (no venv)"
	@echo "  make run            Run main.py (uses venv python if available)"
	@echo "  make scan           Run 'main.py scan' (set HOST, optional PORTS/TIMEOUT/OUT)"
	@echo "  make report-dir     Show reports directory"
	@echo "  make clean          Remove .venv"
	@echo ""
	@echo "Examples:"
	@echo "  make install"
	@echo "  make scan HOST=127.0.0.1 PORTS=1-1024 TIMEOUT=0.8 OUT=scan.json"

venv:
	@echo ">> Creating virtual environment in $(VENV)"
	@test -d $(VENV) || $(PY) -m venv $(VENV)
	@echo ">> To activate: $(ACTIVATE_HINT)"

install: venv
	@echo ">> Upgrading pip/setuptools/wheel in venv"
	@$(VENVPY) -m pip install --upgrade pip setuptools wheel
	@echo ">> Installing requirements.txt in venv"
	@$(VENVPIP) install -r requirements.txt
	@echo ""
	@echo "[+] Installed into $(VENV). Activate with: $(ACTIVATE_HINT)"

install-user:
	@echo ">> Upgrading user pip"
	@$(PIP) install --user --upgrade pip setuptools wheel
	@echo ">> Installing requirements.txt for current user"
	@$(PIP) install --user -r requirements.txt

# Prefer venv python if it exists; otherwise fallback to system python
run:
	@echo ">> Running main.py"
	@if [ -x "$(VENVPY)" ]; then \
		"$(VENVPY)" main.py; \
	else \
		$(PY) main.py; \
	fi

menu: run

# Example:
#   make scan HOST=127.0.0.1 PORTS=1-1024 TIMEOUT=0.8 OUT=scan.json
scan:
	@if [ -z "$(HOST)" ]; then \
		echo "Usage: make scan HOST=target [PORTS=top1k|1-1024] [TIMEOUT=1.0] [OUT=scan.json]"; \
		exit 1; \
	fi
	@echo ">> Scanning $(HOST) PORTS=$(PORTS) TIMEOUT=$(TIMEOUT) OUT=$(OUT)"
	@PYBIN="$(PY)"; \
	if [ -x "$(VENVPY)" ]; then PYBIN="$(VENVPY)"; fi; \
	CMD_OPTS="scan $(HOST) --ports \"$${PORTS:-top1k}\" --timeout \"$${TIMEOUT:-1.0}\""; \
	if [ -n "$(OUT)" ]; then CMD_OPTS="$$CMD_OPTS --out \"$(OUT)\""; fi; \
	echo ">> $$PYBIN main.py $$CMD_OPTS"; \
	eval "$$PYBIN main.py $$CMD_OPTS"

report-dir:
	@echo $$HOME/.hackerlife/reports

clean:
	@echo ">> Removing $(VENV)"
	@rm -rf "$(VENV)"
