# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# Install system deps if needed (kept minimal)
RUN pip install --no-cache-dir --upgrade pip

# Copy and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app.py /app/app.py

# Expose (for clarity; Cloud Run sets networking)
EXPOSE 8080

# Use gunicorn; Cloud Run sets $PORT
CMD exec gunicorn --bind :$PORT --workers 2 --threads 8 --timeout 0 app:app
