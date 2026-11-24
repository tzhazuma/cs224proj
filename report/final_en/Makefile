# Build the final paper: `make` = PDF; `make figures` = regenerate figures/tables/numbers (paper-results lane).
SHELL := /bin/bash
export PATH := $(HOME)/.local/bin:$(PATH)
export FONTCONFIG_FILE := $(CURDIR)/fontconfig/fonts.conf
PYTHON ?= python3
# Lanes build into their own OUTDIR (e.g. make pdf OUTDIR=build_front) so concurrent builds do not clash;
# only the default OUTDIR=build refreshes main.pdf (parent).
OUTDIR ?= build
.PHONY: all pdf figures check clean
all: pdf
figures:
	$(PYTHON) figures/make_figures.py
pdf:
	latexmk -xelatex -interaction=nonstopmode -halt-on-error -outdir=$(OUTDIR) main.tex
	@if [ "$(OUTDIR)" = build ]; then cp build/main.pdf main.pdf; fi
check:
	@grep -nE '^! |Overfull|Citation .* undefined|Reference .* undefined|There were undefined' $(OUTDIR)/main.log || echo "clean"
	@pdfinfo $(OUTDIR)/main.pdf | grep Pages
clean:
	rm -rf build build_*
