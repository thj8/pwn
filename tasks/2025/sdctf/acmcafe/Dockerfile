FROM ubuntu:22.04

RUN apt-get update
RUN apt-get update && apt-get install -y socat libseccomp-dev

RUN useradd -m arbitrary

WORKDIR /
COPY start.sh /start.sh
RUN chmod 755 /start.sh

EXPOSE 1337

COPY arbitrary /
COPY flag.txt /home/arbitrary/flag.txt
RUN chown root:root /home/arbitrary/flag.txt
RUN chmod 644 /home/arbitrary/flag.txt
RUN chmod +x /arbitrary

CMD ["/start.sh"]