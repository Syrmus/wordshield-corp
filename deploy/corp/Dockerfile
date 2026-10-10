# Build only on a provisioning machine without user documents or secrets.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS dependencies
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    libreoffice-writer libseccomp2 fonts-dejavu-core fonts-liberation ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/wordshield
COPY deploy/corp/requirements-app.txt /tmp/requirements-app.txt
RUN pip install --no-cache-dir -r /tmp/requirements-app.txt

FROM dependencies AS base
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps '.[corp]'
COPY tools/install_gliner_weights.py tools/install_privacy_ru.py tools/provision_privacy_tokenizer.py ./tools/

FROM base AS tests
RUN pip install --no-cache-dir pytest==9.1.1 python-docx==1.2.0
COPY tests ./tests
COPY tools ./tools
CMD ["python", "-m", "pytest", "-q"]

FROM dependencies AS runtime
ARG TORCH_FLAVOR=cuda
RUN if [ "$TORCH_FLAVOR" = cpu ]; then \
      pip install --no-cache-dir torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu; \
    elif [ "$TORCH_FLAVOR" = cuda ]; then pip install --no-cache-dir torch==2.14.0; \
    else echo 'TORCH_FLAVOR must be cpu or cuda' >&2; exit 1; fi
COPY deploy/corp/requirements-models.txt /tmp/requirements-models.txt
RUN pip install --no-cache-dir -r /tmp/requirements-models.txt && pip check \
    && pip freeze > /opt/wordshield/installed-packages.txt
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps '.[corp]'
COPY tools/install_gliner_weights.py tools/install_privacy_ru.py tools/provision_privacy_tokenizer.py ./tools/
ENV HOME=/tmp WORDSHIELD_EDITION=corp OTEL_SDK_DISABLED=true
USER 10001:10001
CMD ["python", "-m", "uvicorn", "wordshield.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8844", "--workers", "1", "--no-access-log", "--proxy-headers"]
