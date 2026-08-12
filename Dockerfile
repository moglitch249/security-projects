FROM python:3.12-slim

LABEL maintainer="ScopeHunter"
LABEL description="Technology-Aware Security Assessment Assistant"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY scopehunter/ ./scopehunter/

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Create reports directory
RUN mkdir -p /reports

# Default entrypoint
ENTRYPOINT ["scopehunter"]
CMD ["--help"]

# Usage examples (in comments):
# docker build -t scopehunter .
# docker run --rm -it scopehunter                                          # Interactive
# docker run --rm -it scopehunter -t https://target.com -R html -o /reports
# docker run --rm -it -v $(pwd)/reports:/reports scopehunter -t https://target.com
