FROM ibmfunctions/action-python-v3.7

RUN pip install --upgrade pip
RUN pip install certbot
RUN pip install PyJwt==1.7.1
RUN mkdir -p /home/app/
COPY *.sh /home/app/
