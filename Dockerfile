#
# Dockerfile: Ubuntu-based image for Python security tools
#

# Use an Ubuntu LTS base image (e.g., 22.04)
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
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

# Create a non-root user named "scanner"
RUN useradd -ms /bin/bash scanner

# Set the working directory
WORKDIR /app

# Create and activate a Python virtual environment
ENV VIRTUAL_ENV=/app/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Upgrade pip (pin to a specific version if desired)
RUN pip3 install --no-cache-dir --upgrade pip==23.3.2

# Copy application source code first (includes requirements.txt)
COPY src/ ./src/
COPY .env .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r src/requirements.txt

# Create a data directory and fix ownership for the non-root user
RUN mkdir -p ./data/scan_results && chown -R scanner:scanner ./data

# Create cache directory with proper permissions
RUN mkdir -p ./.cache && chown -R scanner:scanner ./.cache

# Give scanner user access to .env
RUN chown scanner:scanner .env

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONPATH=/app/src
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Default entrypoint to run the FastAPI server
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]