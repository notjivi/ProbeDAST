.PHONY: install lab lab-down test scan-dvwa scan-juiceshop scan-webgoat api dashboard ablation

install:
	pip install -r requirements.txt
	playwright install chromium

lab:
	docker compose up -d dvwa juice-shop webgoat

lab-full:
	docker compose up -d

lab-down:
	docker compose down

test:
	pytest -v

scan-dvwa:
	python -m probedast.cli scan --config recipes/dvwa.json --report-out dvwa_report.md --report-fmt markdown

scan-juiceshop:
	python -m probedast.cli scan --config recipes/juiceshop.json --report-out juiceshop_report.md --report-fmt markdown

scan-webgoat:
	python -m probedast.cli scan --config recipes/webgoat.json --report-out webgoat_report.md --report-fmt markdown

ablation:
	python -m benchmark.ablation --recipe recipes/dvwa.json

api:
	uvicorn probedast.api:app --reload --port 8000

dashboard:
	python -m http.server 8080 --directory dashboard
