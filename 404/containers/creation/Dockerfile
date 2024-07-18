FROM python:3.7-alpine

# install GCC to speedup SQLAlchemy and mysql_config
# this line may hang sometimes, see the README
RUN apk add --no-cache gcc musl-dev linux-headers mariadb-dev build-base

COPY ./creation/requirements.txt ./requirements.txt
RUN pip install -r ./requirements.txt


# Set CWD in container to /app
WORKDIR /app

ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0

RUN mkdir ./logs
ADD ./shared ./
COPY ./creation ./
CMD ["flask", "run"]