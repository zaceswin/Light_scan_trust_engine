# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


# Install System Build Dependencies required by pip
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml requirements.txt ./
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r  requirements.txt 
    
COPY . .
RUN pip install --no-cache-dir .

ENTRYPOINT ["trust-score"]
CMD ["--help"]
