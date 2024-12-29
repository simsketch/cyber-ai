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
    && rm -rf /var/lib/apt/lists/*

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

# Copy your Python requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application source code
COPY src/ ./src/
COPY .env .

# Create a data directory and fix ownership for the non-root user
RUN mkdir -p ./data/scan_results && chown -R scanner:scanner ./data

# Give scanner user access to .env
RUN chown scanner:scanner .env

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONPATH=/app

# Default entrypoint to run your Python script
ENTRYPOINT ["python3", "src/main.py"]