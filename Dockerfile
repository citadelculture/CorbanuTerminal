FROM ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc
ENV DEBIAN_FRONTEND=noninteractive
ARG WORKER_UID=1001
ARG WORKER_GID=1001
RUN apt-get -o Acquire::Retries=0 update \
 && apt-get -o Acquire::Retries=0 install -y --no-install-recommends \
    build-essential ca-certificates curl git python3 python3-venv pkg-config \
    libcap-dev libssl-dev zlib1g-dev clang cmake bubblewrap ripgrep \
 && dpkg-query -W -f='${Package}\t${Version}\n' > /native-packages.tsv \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid "$WORKER_GID" issue1177 \
 && useradd --uid "$WORKER_UID" --gid "$WORKER_GID" --no-create-home --home-dir /owned/home issue1177
ENV HOME=/owned/home PATH=/owned/toolchain/bin:/owned/bin:/usr/bin:/bin
WORKDIR /owned/source
CMD ["/usr/bin/python3", "-I", "-B", "/control/worker.py"]
