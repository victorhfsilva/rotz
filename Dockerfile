FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/root/.local/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    ansible \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY playbook.yml /tmp/playbook.yml
COPY .env /root/.env

RUN ansible-playbook /tmp/playbook.yml -c local && \
    rm /tmp/playbook.yml

COPY config/subfinder/provider-config.yaml /root/.config/subfinder/provider-config.yaml
COPY config/notify/provider-config.yaml /root/.config/notify/provider-config.yaml
COPY config/puredns/resolvers.txt /root/.config/puredns/resolvers.txt

WORKDIR /app

COPY recon.py /app/recon.py

VOLUME ["/app/output", "/app/input", "/app/workflows", "/app/wordlists",  "/app/gf", "/app/scripts"]

ENTRYPOINT ["rayder"]
CMD ["-w", "/app/workflows/main.yaml"]