FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SEMGREP_BIN=/opt/semgrep/bin/semgrep \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
WORKDIR /app

# Optional local wheel cache (backend/wheels). If it holds the full Semgrep set, the install is
# offline and fast; otherwise it falls back to downloading from PyPI.
COPY wheels /wheels

# Semgrep lives in its own virtualenv so its dependencies never clash with FastAPI's
RUN python -m venv /opt/semgrep \
    && ( /opt/semgrep/bin/pip install --no-cache-dir --no-index --find-links /wheels semgrep==1.180.0 \
         || /opt/semgrep/bin/pip install --no-cache-dir --timeout 60 --retries 10 semgrep==1.180.0 )

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 60 --retries 10 -r requirements.txt

# Gitleaks 8.30.1 and Trivy 0.75.0 ship in backend/tools, so the build needs no GitHub download
COPY tools /tmp/tools
RUN tar -xzf /tmp/tools/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && tar -xzf /tmp/tools/trivy.tar.gz -C /usr/local/bin trivy \
    && gitleaks version && trivy --version | head -1 \
    && rm -rf /tmp/tools

COPY app ./app
COPY rules ./rules
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
