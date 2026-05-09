FROM python:3.12-slim@sha256:6026d9374020066a85690cabdb66f5d06a2dd606e756c7082fccdaaaf6d048dd

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    useradd --no-create-home --shell /bin/false appuser

COPY src/ ./src/

USER appuser
ENTRYPOINT ["python", "/app/src/main.py"]
