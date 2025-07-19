# Multi-stage build for smaller production image
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user
RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/mcpuser/.local

# Copy application code
COPY src/ ./src/
COPY demo/ ./demo/

# Copy configuration files
COPY pyproject.toml .

# Create directories and set permissions
RUN mkdir -p /app/logs /app/data && \
    chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Add local Python packages to PATH
ENV PATH=/home/mcpuser/.local/bin:$PATH

# Set Python path
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["python", "-m", "src.gateway", "--host", "0.0.0.0", "--port", "8080"]