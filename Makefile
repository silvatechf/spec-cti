.PHONY: install test lint lab-up lab-down lab-reset ctf-start report format help

PYTHON := python3
PIP := $(PYTHON) -m pip
COMPOSE := docker-compose

help:
	@echo "CyberLab-Enterprise — available targets:"
	@echo "  install     Install Python dependencies"
	@echo "  lab-up      Build and start the full lab (docker-compose up -d) + seed DB + hide CTF flags"
	@echo "  lab-down    Stop and remove all lab containers"
	@echo "  lab-reset   Full teardown + rebuild + reseed"
	@echo "  test        Run pytest with coverage (>=70%)"
	@echo "  lint        Run Bandit (SAST) and Safety (dependency scan)"
	@echo "  ctf-start   Start CTF mode (deploy flags + open scoreboard)"
	@echo "  report      Generate executive + technical reports (HTML + PDF)"
	@echo "  format      Run black + isort"

install:
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

lab-up:
	$(COMPOSE) up -d --build
	$(PYTHON) scripts/setup_lab.py

lab-down:
	$(COMPOSE) down

lab-reset:
	$(COMPOSE) down -v
	$(PYTHON) scripts/reset_lab.py
	$(COMPOSE) up -d --build
	$(PYTHON) scripts/setup_lab.py

test:
	$(PYTHON) -m pytest tests/ --cov=src --cov-report=term-missing --cov-report=html --cov-fail-under=70

lint:
	$(PYTHON) -m bandit -r src/ -ll -x tests
	$(PYTHON) -m safety check -r requirements.txt

format:
	$(PYTHON) -m black src/ tests/ scripts/
	$(PYTHON) -m isort src/ tests/ scripts/

ctf-start:
	$(PYTHON) -m src.cli.main ctf start

report:
	$(PYTHON) -m src.cli.main report generate --format html --format pdf

health:
	$(PYTHON) scripts/health_check.py
