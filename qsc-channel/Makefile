PY ?= python
test:
	$(PY) -m pytest -q
bench:
	$(PY) scripts/bench_all.py
figures:
	$(PY) scripts/make_figures.py
notebook:
	jupyter nbconvert --to notebook --execute --inplace main.ipynb
all: test bench figures
	$(PY) scripts/build_report.py
	$(PY) scripts/check_repo.py
