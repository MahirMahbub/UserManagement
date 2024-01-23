# It is demo application of user management
## Features
* Customized password table for users
* Phone OTP and email link for reset password and account verification
* Using twillo for OTP and MailGun for Email verification.


## to use fake smtp server

```shell
docker run --rm -it -p 3000:80 -p 2525:25 rnwood/smtp4dev
```