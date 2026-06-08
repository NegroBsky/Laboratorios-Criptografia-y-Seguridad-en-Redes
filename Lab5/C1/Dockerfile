FROM ubuntu:16.10
# Actualizar repositorios a old-releases
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
# Instalar cliente OpenSSH
RUN apt-get update && apt-get install -y openssh-client tcpdump && rm -rf /var/lib/apt/lists/*
CMD ["tail", "-f", "/dev/null"]