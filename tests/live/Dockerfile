FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping nftables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir '.[dev]'
ENV PINGO_LIVE=1
CMD ["python", "-m", "pytest", "-q", "-m", "live", "tests/live"]
