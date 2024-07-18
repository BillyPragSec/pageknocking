FROM mitmrev-base:latest

# Set CWD in container to /app
WORKDIR /app

ADD ./mitm/data ./data
ADD ./mitm/scripts ./
ADD ./shared ./


ADD ./mitm/init-mitm.sh ./init-mitm.sh
RUN chmod +x ./init-mitm.sh
RUN mkdir ./logs
ENV MITM_PORT 8080
CMD ["/bin/sh", "-c", "./init-mitm.sh"]
