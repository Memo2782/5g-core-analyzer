FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for pyshark/tshark
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libglib2.0-0 \
    libpcre3-dev \
    libxml2 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/uploads /app/data_samples

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Use gunicorn for production
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "web_app:app"]
