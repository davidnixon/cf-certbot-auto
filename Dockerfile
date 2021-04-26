FROM openwhisk/actionloop-v2:latest as builder
FROM certbot/certbot

RUN mkdir -p /proxy/bin /proxy/lib /proxy/action
WORKDIR /proxy
COPY --from=builder /bin/proxy /bin/proxy
ADD lib/launcher.py /proxy/lib/launcher.py
ADD bin/compile /proxy/bin/compile
ENV OW_COMPILER=/proxy/bin/compile
 
RUN apk add curl
WORKDIR /home/app/
COPY *.sh ./
#ENTRYPOINT [ "/bin/sh" ]
#ENTRYPOINT [ "certbot", "--version"]
ENTRYPOINT ["/bin/proxy"]
