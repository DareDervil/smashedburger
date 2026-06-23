FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persist the SQLite DB on a mounted volume at /data
ENV DB_PATH=/data/smashedburger.db

EXPOSE 8080

CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--worker-class", "gevent", \
     "--workers", "1", \
     "--worker-connections", "100", \
     "--timeout", "300", \
     "--access-logfile", "-", \
     "--access-logformat", "%(h)s %(l)s %(u)s [%(t)s] \"%(r)s\" %(s)s %(b)s", \
     "main:app"]
