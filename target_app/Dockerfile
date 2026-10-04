FROM python:3.12-slim

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY cert ./cert

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 443

CMD ["python", "app.py"]