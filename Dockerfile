FROM rust:1.75-slim as rust-builder
WORKDIR /build
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY spidercrawl/ ./spidercrawl/
RUN cd spidercrawl && cargo build --release

FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libcairo2 libdrm2 libgbm1 libglib2.0-0 libgtk-3-0 libnss3 libnspr4 \
    libpango-1.0-0 libpangocairo-1.0-0 libx11-6 libx11-xcb1 libxcb1 \
    libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 libxrender1 \
    libxshmfence1 libxkbcommon0 libxcursor1 libxi6 libxtst6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /build/spidercrawl/target/release/libspidercrawl.so /app/spidercrawl.so

COPY pyproject.toml ./
COPY trustcheck_agent/ ./trustcheck_agent/

RUN pip install --no-cache-dir -e . && playwright install chromium

ENV PYTHONPATH=/app
ENV PORT=8000

CMD uvicorn trustcheck_agent.main:app --host 0.0.0.0 --port $PORT
