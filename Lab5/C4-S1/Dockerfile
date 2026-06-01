FROM ubuntu:22.10

RUN sed -i 's|http://archive.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y openssh-client openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Crear usuario prueba
RUN useradd -m -s /bin/bash prueba && \
    echo "prueba:prueba" | chpasswd

# Configurar servidor SSH
RUN mkdir /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]