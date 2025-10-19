FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    nodejs \
    npm \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create user first
RUN useradd -m -u 1000 mcp

# Install uv for uvx (install for the mcp user)
USER mcp
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/mcp/.cargo/bin:/home/mcp/.local/bin:$PATH"

# Switch back to root for setup
USER root
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY proxy_server.py .
# COPY mcp_config.json .
COPY mcp_config.schema.json .
COPY version.py .

# Create data directory
RUN mkdir -p /data && chmod 755 /data

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

# Set ownership and switch to non-root user
RUN chown -R mcp:mcp /app /data /home/mcp/.local
USER mcp

# Ensure PATH includes uv for the mcp user
ENV PATH="/home/mcp/.cargo/bin:/home/mcp/.local/bin:$PATH"

# # Pre-install MCP server dependencies to avoid startup delays
# RUN npx -y @modelcontextprotocol/server-sequential-thinking --help > /dev/null 2>&1 || true
# RUN npx -y firecrawl-mcp --help > /dev/null 2>&1 || true
# RUN uvx --help mcp-server-time > /dev/null 2>&1 || true
# RUN uvx --help basic-memory > /dev/null 2>&1 || true

CMD ["python", "proxy_server.py"]
