const crypto = require("crypto")

module.exports = (secret, {
    header = "x-shoppy-signature", //header name where the signature is expected
    algorithm = "sha512", //HMAC algorithm to use
    encoding = "hex", //encoding of the signature
    limit = 10 * 1024 * 1024, //maximum payload size to prevent attacks (default: 10MB)
    statusCode = 401, //HTTP status code to send when signature verification fails
    message = "Invalid signature" //message to send when signature verification fails
} = {}) => {
    if (!secret || typeof secret !== "string") {
        throw new Error("A valid secret string must be provided for hmacverify.")
    }

    return (req, res, next) => {
        if (req.complete) {
            return res.status(500).send("Stream already consumed. Ensure hmacverify is used before other body parsers.")
        }

        const chunks = []
        let bodySize = 0

        req.on("data", chunk => {
            bodySize += chunk.length

            if (bodySize > limit) {
                return res.status(413).send("Payload Too Large")
            }

            chunks.push(chunk)
        })

        req.on("end", () => {
            if (bodySize > limit) return

            req.rawBody = Buffer.concat(chunks).toString("utf-8")

            try {
                req.body = JSON.parse(req.rawBody)
            } catch (_) {
                return res.status(400).send("Invalid JSON payload")
            }

            try {
                //get signature
                const signatureHeader = req.headers[header]
                if (!signatureHeader) return res.status(400).send("Missing signature header")

                //create hmac
                const hmac = crypto.createHmac(algorithm, secret)

                //compare signatures
                const expectedSignature = Buffer.from(hmac.update(req.rawBody, "utf-8").digest(encoding))
                const actualSignature = Buffer.from(signatureHeader)
                if (expectedSignature.length !== actualSignature.length || !crypto.timingSafeEqual(expectedSignature, actualSignature)) {
                    return res.status(statusCode).send(message)
                }

                next()
            } catch (err) {
                res.status(500).send("Error during signature verification")
            }
        })
    }
}