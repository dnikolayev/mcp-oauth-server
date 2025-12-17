FROM python:3.14-slim

WORKDIR /app

# Install system dependencies if needed (e.g. curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose ports
EXPOSE 8080 8042

# Define entrypoint (via manage.py)
CMD ["python", "manage.py", "serve", "--host", "0.0.0.0", "--port", "8042"]
