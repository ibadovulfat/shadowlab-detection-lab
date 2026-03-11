
.PHONY: install run docker-build docker-run clean

install:
\tpython -m venv venv && . venv/bin/activate && pip install -r requirements.txt

run:
\tpython app.py

docker-build:
\tdocker build -t shadowlab-api .

docker-run:
\tdocker run --rm -p 8000:8000 --name shadowlab shadowlab-api

clean:
\trm -rf shadowlab_out __pycache__ */__pycache__
