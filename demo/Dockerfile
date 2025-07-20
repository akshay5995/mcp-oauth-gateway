# Dockerfile for FastMCP Calculator Demo Service
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY fastmcp_server.py .

# Expose port
EXPOSE 3001

# Run the FastMCP server
CMD ["python", "fastmcp_server.py"]