
.PHONY: install run docker-build docker-run clean

install:
\tpython -m venv venv && . venv/bin/activate && pip install -r requirements.txt

run:
\tstreamlit run app.py

docker-build:
\tdocker build -t shadowlab-web .

docker-run:
\tdocker run --rm -p 8501:8501 --name shadowlab shadowlab-web

clean:
\trm -rf shadowlab_out __pycache__ */__pycache__
