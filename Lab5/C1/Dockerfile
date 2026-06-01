FROM ubuntu:16.10

RUN sed -i 's|http://archive.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y openssh-client && \
    rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]