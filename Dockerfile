FROM node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS assets
WORKDIR /assets
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY scripts/vendor-pdfjs.mjs scripts/vendor-pdfjs.mjs
RUN node scripts/vendor-pdfjs.mjs

FROM python:3.13-slim-trixie@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd -g 10001 app && useradd -u 10001 -g app -m app
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && python -m pip uninstall -y pip
COPY . .
COPY --from=assets /assets/static/vendor/pdfjs/ /app/static/vendor/pdfjs/
RUN mkdir -p /data/private /app/staticfiles && chown -R app:app /data /app
USER app
RUN python manage.py collectstatic --noinput
EXPOSE 8000
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--timeout", "120", "--max-requests", "1000", "--max-requests-jitter", "100", "--error-logfile", "-", "--no-control-socket"]
