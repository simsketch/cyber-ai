#
# Dockerfile: Ubuntu-based image for Python security tools
#

# Use an Ubuntu LTS base image (e.g., 22.04)
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    nmap \
    dnsutils \
    git \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    cargo \
    rustc \
    python3-venv \
    libcurl4-openssl-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Update CA certificates
RUN update-ca-certificates

# Create a non-root user
RUN useradd -ms /bin/bash scanner

# Set working directory
WORKDIR /app

# Create and activate virtual environment
ENV VIRTUAL_ENV=/app/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Upgrade pip
RUN pip3 install --no-cache-dir --upgrade pip==23.3.2

# Copy application files
COPY backend/src/ ./src/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r src/requirements.txt

# Create data directory and set permissions
RUN mkdir -p ./data/scan_results && chown -R scanner:scanner ./data
RUN mkdir -p ./.cache && chown -R scanner:scanner ./.cache
RUN chown -R scanner:scanner ./src

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONPATH="/app/src:$PYTHONPATH"
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]