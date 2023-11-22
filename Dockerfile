FROM python:3.10.9-alpine
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENV HOME=/home/app

RUN mkdir -p $HOME
RUN mkdir $HOME/static
RUN mkdir $HOME/media
RUN mkdir $HOME/logs
RUN mkdir $HOME/templates

# where the code lives
WORKDIR $HOME

COPY ./requirements.txt /requirements.txt

RUN pip install --upgrade pip

RUN apk update && apk add bash
RUN apk add --update --no-cache postgresql-client jpeg-dev libffi-dev
RUN apk add --update --no-cache --virtual .tmp-build-deps \
      gcc libc-dev linux-headers postgresql-dev musl-dev zlib zlib-dev
RUN pip install -r /requirements.txt
RUN apk del .tmp-build-deps

# copy entrypoint.sh
COPY ./entrypoint.sh ./
RUN sed -i 's/\r$//g' /home/app/entrypoint.sh
RUN chmod +x /home/app/entrypoint.sh

# copy project
COPY . .

# run entrypoint.sh
ENTRYPOINT ["bash", "/home/app/entrypoint.sh"]