FROM node:24-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS assets
WORKDIR /assets
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY scripts/vendor-pdfjs.mjs scripts/vendor-pdfjs.mjs
RUN node scripts/vendor-pdfjs.mjs

FROM python:3.13.18-alpine@sha256:bbc0290146ebe0a8b9a8ed07d3f2c7bdeb4d917fc93300a4e47490c8b5a11b48
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt && python -m pip uninstall -y pip
COPY manage.py pyproject.toml ./
COPY accounts/ accounts/
COPY audit/ audit/
COPY config/ config/
COPY vault/ vault/
COPY templates/ templates/
COPY static/ static/
COPY --from=assets /assets/static/vendor/pdfjs/ /app/static/vendor/pdfjs/
RUN mkdir -p /data/private /app/staticfiles && chown -R app:app /data /app
USER app
RUN python manage.py collectstatic --noinput
EXPOSE 8000
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--timeout", "120", "--max-requests", "1000", "--max-requests-jitter", "100", "--error-logfile", "-", "--no-control-socket"]
