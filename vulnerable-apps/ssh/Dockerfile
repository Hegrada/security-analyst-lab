FROM alpine:latest

# Install OpenSSH
RUN apk add --no-cache openssh

# VULNERABLE CONFIGURATION
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config && \
    echo "StrictModes no" >> /etc/ssh/sshd_config && \
    echo "X11Forwarding yes" >> /etc/ssh/sshd_config && \
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config && \
    echo "Banner /etc/ssh/banner.txt" >> /etc/ssh/sshd_config

# Create weak credentials
RUN echo "root:toor" | chpasswd && \
    echo "admin:admin123" | chpasswd && \
    echo "test:test123" | chpasswd

# Create banner
RUN echo "====================================" > /etc/ssh/banner.txt && \
    echo "  VULNERABLE SSH SERVER" >> /etc/ssh/banner.txt && \
    echo "  Credentials: root/toor" >> /etc/ssh/banner.txt && \
    echo "====================================" >> /etc/ssh/banner.txt

# Start SSH
CMD ["/usr/sbin/sshd", "-D", "-e"]
