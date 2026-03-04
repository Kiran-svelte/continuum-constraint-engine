FROM python:3.11-slim

WORKDIR /app

# Install system deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY constraint_engine.py .

# Render uses PORT env var
EXPOSE 10000

CMD gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 2 --timeout 120 constraint_engine:app
