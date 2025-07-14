FROM ubuntu:24.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd

RUN useradd -m ctf

WORKDIR /home/ctf

RUN cp -R /usr/lib* /home/ctf

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
COPY ./flag /home/ctf/flag
COPY ./vul2 /home/ctf/vul2


RUN chmod 755 /home/ctf
RUN chmod 744 /home/ctf/flag
RUN chown -R root:root /start.sh /home/ctf/vul2 /home/ctf/ && rm /home/ctf/.profile /home/ctf/.bashrc /home/ctf/.bash_logout && chmod +x /start.sh /home/ctf/vul2 && chown root:root /home/ctf
CMD ["/start.sh"]

EXPOSE 9999
