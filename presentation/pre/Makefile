# Build the pre: `make` = figures + PDF; `make figures` re-renders figures from whatever results exist.
SHELL := /bin/bash
export PATH := $(HOME)/.local/bin:$(PATH)
# Local fontconfig (Fira from the user's TeX Live) so metropolis finds "Fira Sans" by name.
export FONTCONFIG_FILE := $(CURDIR)/fontconfig/fonts.conf
PYTHON ?= python3
FIGS := figures/probes.pdf figures/prf1.pdf figures/pareto.pdf figures/heatmap.pdf

.PHONY: all figures pdf pngs check clean
all: figures pdf

figures:
	$(PYTHON) figures/make_figures.py

pdf:
	latexmk -xelatex -interaction=nonstopmode -halt-on-error -outdir=build main.tex
	cp build/main.pdf main.pdf

# page previews for layout review
pngs: pdf
	rm -rf build/pages && mkdir -p build/pages
	pdftoppm -r 50 -png main.pdf build/pages/p

# errors, overfull boxes and missing references in the last build log
check:
	@grep -nE "^!|Overfull|Undefined control|undefined references|Could not find" build/main.log || echo "clean: no errors, overfull boxes or missing fonts"

clean:
	latexmk -C -outdir=build main.tex
	rm -rf build main.pdf
