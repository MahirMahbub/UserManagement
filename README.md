# It is demo application of user management
## Features
* Customized password table for users
* Phone OTP and email link for reset password and account verification
* Using twillo for OTP and MailGun for Email verification.
* Creating Super Admin from System
* Create Admin by Super Admin
* Register Admin
* Admin Account approval by Super Admin
* All User Account Verify by Email and OTP
* All User Reset Password by Email and OTP
* All User Sign in (Bearer Jwt Token).
* OTP expires in 5 minutes. 
* Password Reset/Verification Link expires in 30 minutes.

## Technology
* Backend Web Framework: Django REST and Django Web Framework 
* Auth: Json Web Token(JWT) Bearer
* Follow  open standard (RFC 7519).
* Use for authorization
* Includes role and permissions in claims.
* Containerization: Docker(esp. Docker-compose)
* SMTP Service: Mailgun
* OTP Service: Twillo
* Database: SQLite for Development, Postgres for Deployment
* API Documentation: OpenAPI Swagger

## Database
* Separate Password Table.
* Salt is stored in Child User tables to encrypt a special key for finding the password.
* Used bcrypt algorithm for hashing the password and special key.
* The salt is incorporated into the hash for bcrypt.
* Permissions maintained through a master table.
![image](https://github.com/user-attachments/assets/3932423e-3ac2-40f7-85b4-d3b094eecbf5)

![image](https://github.com/user-attachments/assets/07970b55-bf5e-4fae-bcd7-29ed6207cd53)

## RestAPI Design
![image](https://github.com/user-attachments/assets/55e7267f-31bd-4c28-bf79-63f34677dfe2)

## Service Architecture
![image](https://github.com/user-attachments/assets/4a0b9023-2083-4457-a45f-5fe8cc808dd0)





