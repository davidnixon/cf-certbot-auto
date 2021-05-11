FROM ibmfunctions/action-python-v3.7

RUN pip install --upgrade pip
RUN pip install certbot
RUN pip install jwt
RUN curl -fsSL https://clis.cloud.ibm.com/install/linux | sh
RUN ibmcloud cf install
RUN mkdir -p /home/app/
COPY *.sh /home/app/
