# Makefile for AAM Security Paper
# Requires: pdflatex, bibtex

MAIN = main
FIGURES_DIR = figures
FIGURES = latency_comparison hybrid_architecture system_architecture

.PHONY: all clean figures pdf

all: figures pdf

# Compile TikZ figures to PDF
figures:
	@echo "Compiling figures..."
	@for fig in $(FIGURES); do \
		echo "  Building $$fig.pdf..."; \
		cd $(FIGURES_DIR) && pdflatex -interaction=nonstopmode $$fig.tex > /dev/null 2>&1; \
		cd ..; \
	done
	@echo "Figures compiled."

# Compile main document
pdf: figures
	@echo "Compiling paper..."
	pdflatex -interaction=nonstopmode $(MAIN).tex
	bibtex $(MAIN)
	pdflatex -interaction=nonstopmode $(MAIN).tex
	pdflatex -interaction=nonstopmode $(MAIN).tex
	@echo "Paper compiled: $(MAIN).pdf"

# Clean auxiliary files
clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.lof *.lot *.fls *.fdb_latexmk *.synctex.gz
	rm -f $(FIGURES_DIR)/*.aux $(FIGURES_DIR)/*.log
	@echo "Cleaned auxiliary files."

# Clean everything including PDF
cleanall: clean
	rm -f $(MAIN).pdf $(FIGURES_DIR)/*.pdf
	@echo "Cleaned all files."

# Quick compile (no figures rebuild)
quick:
	pdflatex -interaction=nonstopmode $(MAIN).tex
	@echo "Quick compile done."

# Watch for changes (requires latexmk)
watch:
	latexmk -pdf -pvc $(MAIN).tex
