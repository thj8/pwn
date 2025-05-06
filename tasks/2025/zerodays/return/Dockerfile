FROM pwn.red/jail

COPY --from=ubuntu / /srv
COPY return /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN chmod 755 /srv/app/run