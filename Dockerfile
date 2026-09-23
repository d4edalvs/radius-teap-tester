FROM python:3.12-slim

# cryptography and cffi ship manylinux wheels, so no build toolchain is needed.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TEAP_GUI_DATA=/data

WORKDIR /app

COPY pyproject.toml README.md ./
COPY teap_tester/ ./teap_tester/
COPY teap_gui/ ./teap_gui/
COPY docs/ ./docs/

RUN pip install --no-cache-dir -e '.[gui]'

# SQLite database, the encryption key, and uploaded certificates live here.
# Anyone who can read this volume can read every stored secret.
VOLUME /data

# 8000 collides with too much; the GUI defaults to 8010.
EXPOSE 8010

RUN useradd --create-home --uid 10001 teap && mkdir -p /data && chown teap /data
USER teap

CMD ["uvicorn", "teap_gui.app:app", "--host", "0.0.0.0", "--port", "8010"]
