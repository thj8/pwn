FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    qemu-user \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Set up challenge environment
WORKDIR /chall

RUN useradd -m ctf

# Copy challenge binary and flag
COPY chall /chall/chall
COPY flag.txt /chall/flag.txt

# Set correct permissions
RUN chmod 555 /chall/chall /chall/flag.txt && \
    chmod 555 /chall && \
    chown -R root:root /chall
# Expose port for connection
EXPOSE 1337

USER ctf

# Run the challenge with socat
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'qemu-arm chall'"]