# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# If we had a proper package structure, this would be:
# RUN pip install --no-cache-dir .
# For now, we rely on the script being executable in the root
ENTRYPOINT ["python", "trust_scorer.py"]
CMD ["--help"]
