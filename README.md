# jwt-authentication

This addon is an addon to allow to login eXo Platform with a JWT Token
This authentication mode can be used for normal user access or for API access

JWT authentication require to use RS256 signature algorithm, using a private key for the entity which creates the JWT token, and public for eXo to verify the JWT token.

JWT token is read by default in Authorization header, with format 
Bearer eyJh...CJ9.eyJzdWIiOiIxM...MjM5MDIyfQ.SflKxwRJSM...._adQssw5c

If needed it can be passed as url parameter

## How to install
Launch this commands :
```
cd ${EXO_HOME}
./addon install exo-jwt-authentication
```


## How to configure

Available properties are :

- exo.jwt.issuer : the issuer (sender) of the JWT token. This value must exactly match the "iss" field in the jwt token. Default value : exo.base.url
- exo.jwt.audience : the target audience (receiver) of the JWT token. This value must exactly match the "aud" field in the jwt token. Default value : exo.base.url
- exo.jwt.publicKeyUrl : the url of the public certificate allowing to verify the JWT signature. Certificate can be local (file://path/to/the/cert), or remote (https://url/to/the/cert)
- exo.jwt.header : the header in which the token is. Default value : "Authorization"
- exo.jwt.parameter : the url parameter in which the token is. No default value. If exo.jwt.header is filled, this parameter is ignored. If this option is used, the "Bearer " string is not necessary
- 
