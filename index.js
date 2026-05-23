const crypto = require("crypto")

export default (secret, {
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
            return res.status(500).json({ message: "Stream already consumed. Ensure hmacverify is used before other body parsers." })
        }

        const chunks = []
        let bodySize = 0

        req.on("data", chunk => {
            bodySize += chunk.length

            if (bodySize > limit) {
                res.status(413).json({ message: "Payload too large" })
                req.destroy() //destroy stream to stop receiving more data
                return
            }

            chunks.push(chunk)
        })

        req.on("end", () => {
            if (bodySize > limit) return

            req.rawBody = Buffer.concat(chunks).toString("utf-8")

            try {
                req.body = JSON.parse(req.rawBody)
            } catch (err) {
                console.error("Error parsing JSON payload:", err)
                return res.status(400).json({ message: "Invalid JSON payload" })
            }

            try {
                //get signature
                const signatureHeader = req.header(header)
                if (!signatureHeader) return res.status(400).json({ message: "Missing signature header" })

                //create hmac
                const hmac = crypto.createHmac(algorithm, secret)

                //compare signatures
                const expectedSignature = Buffer.from(hmac.update(req.rawBody, "utf-8").digest(encoding))
                const actualSignature = Buffer.from(signatureHeader)
                if (expectedSignature.length !== actualSignature.length || !crypto.timingSafeEqual(expectedSignature, actualSignature)) {
                    return res.status(statusCode).json({ message })
                }

                next()
            } catch (err) {
                console.error("Error during signature verification:", err)
                res.status(500).json({ message: "Error during signature verification" })
            }
        })
    }
}