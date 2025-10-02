FROM python:3.12-alpine AS builder

ENV PIP_NO_CACHE_DIR=1

RUN apk add --no-cache build-base libffi-dev openssl-dev

WORKDIR /build

COPY requirements.txt ./
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1

RUN adduser -D app
WORKDIR /app

COPY --from=builder /install /usr/local/
COPY . .
RUN mkdir -p databases && chown -R app:app /app

USER app

CMD ["python", "main.py"]
