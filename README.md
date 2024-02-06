# It is demo application of user management

## Features

- Customized password table for users
- Phone OTP and email link for reset password and account verification
- Using twillo for OTP and MailGun for Email verification.

# Setup

## install requirements

```shell
pip install -r requirements.txt
```

## migrate db

```
python manage.py migrate
```

## spin fake smtp server

```shell
docker run --rm -it -p 3000:80 -p 2525:25 rnwood/smtp4dev
```

## start the server on localhost:8000

```shell
python manage.py runserver
```

## API docs

http://127.0.0.1:8000/docs/

## fake smtp server

http://127.0.0.1:3000/
