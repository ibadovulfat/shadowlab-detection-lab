
.PHONY: install run verify smoke-postgres backup restore docker-build docker-run clean

MANIFEST ?= backups/manifest.json

install:
\tpython -m venv venv && . venv/bin/activate && pip install -r requirements.txt

run:
\tpython app.py

verify:
\tpython scripts/ci_verify.py

smoke-postgres:
\tpython scripts/smoke_test_postgres_runtime.py

backup:
\tpython scripts/backup_shadowlab_data.py

restore:
\tpython scripts/restore_shadowlab_data.py $(MANIFEST)

docker-build:
\tdocker build -t shadowlab-api .

docker-run:
\tdocker run --rm -p 8000:8000 --name shadowlab shadowlab-api

clean:
\trm -rf shadowlab_out __pycache__ */__pycache__
