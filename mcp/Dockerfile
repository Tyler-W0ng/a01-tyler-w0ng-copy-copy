FROM python:3.13-slim
# The vulnerability knowledge server. It parses the feed snapshot (JSON, gzip,
# tar, zip, XML) with the standard library only; the sole dependency is the
# MCP SDK (2.x: the server class is MCPServer, at mcp.server.mcpserver).
RUN pip install --no-cache-dir "mcp>=2.2,<3" \
 && useradd --create-home --uid 1000 mcp
WORKDIR /app
COPY server.py loader.py version.py ./
USER mcp
EXPOSE 8000
# python is on PATH for the compose healthcheck (GET /health).
CMD ["python", "server.py"]
