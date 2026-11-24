# Build the revised proposal: `make` = PDF, `make check` = log scan + page count, `make clean`.
SHELL := /bin/bash
export PATH := $(HOME)/.local/bin:$(PATH)
export FONTCONFIG_FILE := $(CURDIR)/fontconfig/fonts.conf
# Only the default OUTDIR=build refreshes proposal_v2.pdf next to the source.
OUTDIR ?= build
.PHONY: all pdf check clean
all: pdf
pdf:
	latexmk -xelatex -interaction=nonstopmode -halt-on-error -outdir=$(OUTDIR) proposal_v2.tex
	@if [ "$(OUTDIR)" = build ]; then cp build/proposal_v2.pdf proposal_v2.pdf; fi
check:
	@grep -nE '^! |Overfull|Citation .* undefined|Reference .* undefined|There were undefined' $(OUTDIR)/proposal_v2.log || echo "clean"
	@pdfinfo $(OUTDIR)/proposal_v2.pdf | grep Pages
clean:
	rm -rf build build_*
