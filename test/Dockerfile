FROM ubuntu:22.04

# Install and configure SSH server
RUN apt-get update && apt-get install -y openssh-server sudo
RUN mkdir -p /var/run/sshd

# Create sudo-enabled user `admin`
RUN useradd admin -s /bin/bash -m
RUN echo "password\npassword\n" | passwd admin
RUN usermod -aG sudo admin

# Run SSH server
CMD ["/usr/sbin/sshd", "-D"]
