FROM certbot/certbot

RUN apk add curl
WORKDIR /home/app/
COPY *.sh ./
ENTRYPOINT [ "/bin/sh" ]
#ENTRYPOINT [ "certbot", "--version"]
