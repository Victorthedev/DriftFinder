FROM python:3.13.7-slim@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689 AS tools

ARG TARGETARCH
ARG TERRAFORM_VERSION=1.13.3
ARG PULUMI_VERSION=3.250.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) TF_SHA=71fc43d92ea09907be5d416d2405a6a9c2d1ceaed633f5e175c0af26e8c4b365; PU_ARCH=x64; PU_SHA=8916fd36ccc96adbd45ca679194b685e3b767d94502ae05610878a6d9870b8f3 ;; \
      arm64) TF_SHA=fa82fb1b08354573467557f33e6a15e7f9e1bba74eb15492f151ca27525d2acc; PU_ARCH=arm64; PU_SHA=deb4bf0d05b4cbaf3adcf82ffa44039ad0ebf039e33338ead8136877a437b4e5 ;; \
      *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/terraform.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip"; \
    echo "${TF_SHA}  /tmp/terraform.zip" | sha256sum -c -; \
    mkdir -p /opt/bin; \
    unzip -q /tmp/terraform.zip -d /opt/bin; \
    curl -fsSLo /tmp/pulumi.tar.gz "https://github.com/pulumi/pulumi/releases/download/v${PULUMI_VERSION}/pulumi-v${PULUMI_VERSION}-linux-${PU_ARCH}.tar.gz"; \
    echo "${PU_SHA}  /tmp/pulumi.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/pulumi.tar.gz -C /opt


FROM python:3.13.7-slim@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689

ENV HOME=/home/driftfinder \
    AWS_CONFIG_FILE=/home/driftfinder/.aws/config \
    AWS_SHARED_CREDENTIALS_FILE=/home/driftfinder/.aws/credentials \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/pulumi:$PATH \
    PULUMI_SKIP_UPDATE_CHECK=true \
    PULUMI_HOME=/home/driftfinder/.pulumi \
    TF_IN_AUTOMATION=1 \
    TF_PLUGIN_CACHE_DIR=/home/driftfinder/.terraform.d/plugin-cache \
    AWS_DEFAULT_REGION=eu-west-1

COPY --from=tools /opt/bin/terraform /usr/local/bin/terraform
COPY --from=tools /opt/pulumi /opt/pulumi

RUN useradd --create-home --uid 1000 driftfinder \
    && mkdir -p /work \
    && chown driftfinder:driftfinder /work \
    && printf '#!/bin/sh\nexec python /app/experiment/run.py "$@"\n' > /usr/local/bin/driftfinder-experiment \
    && chmod 755 /usr/local/bin/driftfinder-experiment

WORKDIR /app

COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-deps --no-build-isolation .

COPY experiment ./experiment
COPY tests ./tests
RUN chown -R driftfinder:driftfinder /app

USER driftfinder

RUN mkdir -p "$TF_PLUGIN_CACHE_DIR" \
    && terraform -chdir=experiment/terraform init -backend=false -input=false \
    && pulumi plugin install resource aws v7.35.0 \
    && chmod -R a+rwX /home/driftfinder

WORKDIR /work

CMD ["bash"]
