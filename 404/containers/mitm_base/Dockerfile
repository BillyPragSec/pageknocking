# pinned version 6.0.0
FROM mitmproxy/mitmproxy:6.0.0

ADD main_dependencies.txt /

RUN sed -i 's/http\:\/\/dl-cdn.alpinelinux.org/https\:\/\/alpine.global.ssl.fastly.net/g' /etc/apk/repositories
RUN apk update --no-cache
RUN apk add --no-cache python3 py-pip python3-dev build-base mariadb-dev
# RUN apt-get update
# RUN apt-get install software-properties-common
# RUN add-apt-repository universe
# RUN apt-get install python3 python3-pip python3-dev build-essential default-libmysqlclient-dev -y

RUN pip3 install --upgrade pip
RUN pip3 --default-timeout=1000 install -r main_dependencies.txt
