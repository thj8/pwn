FROM pwn.red/jail
ENV JAIL_TIME=150

COPY --from=ubuntu / /srv
COPY chall /srv/app/run
COPY zerodays.so /srv/app/zerodays.so
RUN chmod 755 /srv/app/run
