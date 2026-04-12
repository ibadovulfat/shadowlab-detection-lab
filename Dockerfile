
# ShadowLab API — Docker build (Linux base)
FROM python:3.11-slim

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# System deps (for matplotlib fonts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY api /app/api
COPY core /app/core
COPY plugins /app/plugins
COPY services /app/services
COPY static /app/static
COPY lib /app/lib
COPY app.py /app/app.py
COPY database.py /app/database.py
COPY monitor_core.py /app/monitor_core.py
COPY mitre.py /app/mitre.py
COPY report_export.py /app/report_export.py
COPY threat_intelligence.py /app/threat_intelligence.py
COPY config.yaml /app/config.yaml
RUN useradd --create-home --shell /usr/sbin/nologin shadowlab \
    && chown -R shadowlab:shadowlab /app

USER shadowlab

# Expose API port
EXPOSE 8000

CMD ["python", "app.py"]
