FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/alexbers/mtprotoproxy /opt/mtprotoproxy \
    && pip install --no-cache-dir cryptography uvloop
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV PROXY_MODE=process PROXY_PORT=8443 DATA_DIR=/data
CMD ["python", "app.py"]
