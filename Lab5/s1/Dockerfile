FROM ubuntu:22.10
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
# Instalar cliente y servidor
RUN apt-get update && apt-get install -y openssh-server openssh-client tcpdump && rm -rf /var/lib/apt/lists/*
# Crear usuario "prueba" con contraseña "prueba"
RUN useradd -m -s /bin/bash prueba && echo "prueba:prueba" | chpasswd
# Configurar SSHD
RUN mkdir -p /var/run/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]