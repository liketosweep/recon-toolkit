FROM python:3.11-slim

LABEL maintainer="liketosweep"
LABEL description="Recon Toolkit — Automated Web Reconnaissance Framework"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Download default wordlists at build time
RUN mkdir -p wordlists && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
         -o wordlists/subdomains.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
         -o wordlists/directories.txt

# Create reports output dir
RUN mkdir -p reports

ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
