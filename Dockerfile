FROM python:3.10.4

WORKDIR /auth

COPY ./requirements.txt /auth/requirements.txt

ADD .env .env
RUN export `cat .env`

RUN mkdir /auth/logs

RUN pip install -U pip \
    && pip install -r /auth/requirements.txt

COPY . /auth/
