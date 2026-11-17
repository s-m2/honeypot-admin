# Multi-stage build for honeypot-admin
# Stage 1: Build frontend assets with Tailwind
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./
RUN npm install

# Copy frontend config and source
COPY frontend/ .
COPY app/static/css/input.css ./input.css
COPY app/templates ./templates

# Build Tailwind CSS
RUN npx tailwindcss -i ./input.css -o ./style.css --minify


# Stage 2: Python runtime
FROM python:3.12-slim

# Create non-root user
RUN useradd -m -u 1000 honeypot

# Set working directory
WORKDIR /home/honeypot/app

# Create data directory with correct permissions
RUN mkdir -p data && chown -R honeypot:honeypot data

# Install Python dependencies as honeypot user
USER honeypot
COPY --chown=honeypot:honeypot requirements.txt .
RUN pip install --user -r requirements.txt

# Copy compiled CSS from builder stage
COPY --chown=honeypot:honeypot --from=frontend-builder /app/style.css ./app/static/css/style.css

# Copy application code
COPY --chown=honeypot:honeypot . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
