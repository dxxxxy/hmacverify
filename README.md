# hmacverify
> Originally named shoppyhook, made only for shoppy.gg, recoded for general use.
A really simple and lightweight hmac webhook verifier for express.

It will only let webhook requests pass that have a valid signature, meaning that faking purchase webhooks is not possible (provided that you do not leak your secret). The body will then be available as a JSON object in `req.body`.

## Features
- Zero production dependencies.
- Extensive testing with 100% code coverage.
- Safe from common vulnerabilities and attacks.
- Customizable options for flexibility.

## Install
```
npm i hmacverify
```

## Usage
```js
const hmacverify = require("hmacverify")

app.use("/your/webhook/endpoint", hmacverify("secret"))
```

## Options
> If you omit parameters, they will be set to their defaults as shown below. These are also documented in the middleware's code.

```js
header = "x-shoppy-signature", //header name where the signature is expected
algorithm = "sha512", //HMAC algorithm to use
encoding = "hex", //encoding of the signature
limit = 10 * 1024 * 1024, //maximum payload size to prevent attacks (default: 10MB)
statusCode = 401, //HTTP status code to send when signature verification fails
message = "Invalid signature" //message to send when signature verification fails
```

### Parser issues
You need to disable any parser you have enabled for the webhook route, otherwise it will not work as it requires the raw unparsed body.

Example: Using json as a global parser through `app.use(express.json())`, I can simply replace it with this workaround, which applies it globally except for that specific webhook endpoint route.
```js
app.use(req, res, next => req.path != "/your/webhook/endpoint" ? express.json(req, res, next) : next())
```

## Disclaimer
This is for educational purposes only. I am not responsible for any damage caused by this tool.

## License
GPLv3 © dxxxxy