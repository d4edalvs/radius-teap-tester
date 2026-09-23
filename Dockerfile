FROM python:3.12-slim

# cryptography and cffi ship manylinux wheels, so no build toolchain is needed.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TEAP_GUI_DATA=/data

# Create the user and the data directory BEFORE declaring the volume: changes
# to a VOLUME-declared path in later layers are discarded, so chowning after
# the VOLUME line would leave /data root-owned and the app unable to write.
RUN useradd --create-home --uid 10001 teap \
    && mkdir -p /data \
    && chown teap:teap /data

WORKDIR /app

COPY pyproject.toml README.md ./
COPY teap_tester/ ./teap_tester/
COPY teap_gui/ ./teap_gui/
COPY docs/ ./docs/

RUN pip install --no-cache-dir -e '.[gui]' \
    && chown -R teap:teap /app

# SQLite database, the encryption key, and uploaded certificates live here.
# Anyone who can read this volume can read every stored secret.
VOLUME /data

EXPOSE 8010
# Change-of-Authorization listener (RFC 5176). Only needed if a policy server
# will send CoA or Disconnect requests.
EXPOSE 3799/udp

USER teap

CMD ["uvicorn", "teap_gui.app:app", "--host", "0.0.0.0", "--port", "8010"]
