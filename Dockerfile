FROM ibmfunctions/action-python-v3.7

RUN pip install --upgrade pip
RUN pip install certbot

WORKDIR /home/app/
COPY *.sh ./

#ENTRYPOINT ["/bin/proxy"]
