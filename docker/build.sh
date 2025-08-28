docker build -t pwn_ubuntu_2404 .
docker-compose -f docker-compose-2404.yml down
docker-compose -f docker-compose-2404.yml up -d
