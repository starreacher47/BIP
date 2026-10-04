FROM python:3.12-slim

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY app/cert ./cert
COPY analyzer ./analyzer
COPY run.py .
COPY docker/entrypoint.sh ./entrypoint.sh

RUN mkdir -p /app/instance/uploads \
    && chown -R appuser:appuser /app \
    && chmod +x /app/entrypoint.sh

USER appuser

EXPOSE 5000
EXPOSE 443

ENTRYPOINT ["/app/entrypoint.sh"]