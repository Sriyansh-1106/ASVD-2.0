# ASVD 2.0 - Remote Cloud Production Container
FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Generate dataset and train AI model if not present
RUN python data/generate_dataset.py && python ml/train.py

# Set environment
ENV PYTHONPATH=/app
ENV PORT=8000

# Start production server using dynamic PORT assigned by cloud host (Render/AWS/Heroku)
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
