FROM alpine:latest

# Install system dependencies
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    nmap-scripts \
    bind-tools \
    git \
    gcc \
    python3-dev \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

# Create non-root user
RUN adduser -D scanner
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY data/ ./data/

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONPATH=/app

ENTRYPOINT ["python3", "src/main.py"]