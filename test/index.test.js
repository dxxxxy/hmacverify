import { describe, test, expect, vi } from "vitest"
import { EventEmitter } from "events"
import crypto from "crypto"
import hmacverify from "../index.js"

const config = { header: "x-shoppy-signature", algorithm: "sha512", encoding: "hex", limit: 10 * 1024 * 1024, statusCode: 401, message: "Invalid signature" }
const SECRET = "secret"

const createMockRequest = (payload, headers = {}, reqExtraAttributes = {}) => {
    const req = new EventEmitter()
    req.headers = headers
    req.header = name => req.headers[name.toLowerCase()]
    req.destroy = () => req.emit("close")
    Object.assign(req, reqExtraAttributes)

    setTimeout(() => {
        req.emit("data", Buffer.from(payload))
        req.emit("end")
    }, 10)
    return req
}

const signPayload = payload => crypto.createHmac("sha512", SECRET).update(payload, "utf-8").digest("hex")

describe("hmacverify - Webhook Signature Middleware for Express.js", () => {
    test("should throw if no secret is provided", () => {
        expect(() => hmacverify()).toThrow("A valid secret string must be provided for hmacverify.")
    })

    test("should reject requests if body stream is already consumed", async () => {
        const req = createMockRequest("", {}, { complete: true })
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, config)

        middleware(req, res, next)
        await new Promise(resolve => req.on("end", resolve))

        expect(res.status).toHaveBeenCalledWith(500)
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining("Stream already consumed"))
        expect(next).not.toHaveBeenCalled()
    })

    test("should reject requests if payload size exceeds limit", () => {
        const req = new EventEmitter()
        req.header = name => req.headers[name.toLowerCase()]
        req.destroy = () => req.emit("close")
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, config)

        middleware(req, res, next)

        const hugeBuffer = Buffer.alloc(11 * 1024 * 1024, "very big payload")
        req.emit("data", hugeBuffer)

        expect(res.status).toHaveBeenCalledWith(413)
        expect(res.send).toHaveBeenCalledWith("Payload Too Large")
        expect(next).not.toHaveBeenCalled()
    })

    test("should reject requests with non-json payloads", async () => {
        const req = createMockRequest("invalid json")
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, config)

        middleware(req, res, next)
        await new Promise(resolve => req.on("end", resolve))

        expect(res.status).toHaveBeenCalledWith(400)
        expect(res.send).toHaveBeenCalledWith("Invalid JSON payload")
        expect(next).not.toHaveBeenCalled()
    })

    test("should reject requests with missing signature header", async () => {
        const payload = JSON.stringify({ test: 1 })
        const req = createMockRequest(payload)
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, config)

        middleware(req, res, next)
        await new Promise(resolve => req.on("end", resolve))

        expect(res.status).toHaveBeenCalledWith(400)
        expect(res.send).toHaveBeenCalledWith("Missing signature header")
        expect(next).not.toHaveBeenCalled()
    })

    test("should reject requests with invalid signature", async () => {
        const payload = JSON.stringify({ test: 1 })
        const req = createMockRequest(payload, { "x-shoppy-signature": "bad-signature" })
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, config)

        middleware(req, res, vi.fn())
        await new Promise(resolve => req.on("end", resolve))

        expect(res.status).toHaveBeenCalledWith(config.statusCode)
        expect(res.send).toHaveBeenCalledWith(config.message)
        expect(next).not.toHaveBeenCalled()
    })

    test("should reject requests if an error occurs during signature verification", async () => {
        const payload = JSON.stringify({ test: 1 })
        const req = createMockRequest(payload, { "x-shoppy-signature": signPayload(payload) })
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, { ...config, algorithm: "invalid-algo" })

        middleware(req, res, next)
        await new Promise(resolve => req.on("end", resolve))

        expect(res.status).toHaveBeenCalledWith(500)
        expect(res.send).toHaveBeenCalledWith("Error during signature verification")
        expect(next).not.toHaveBeenCalled()
    })

    test("should allow requests with valid signature", async () => {
        const data = { event: "completed" }
        const payload = JSON.stringify(data)
        const req = createMockRequest(payload, { "x-shoppy-signature": signPayload(payload) })
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() }
        const next = vi.fn()
        const middleware = hmacverify(SECRET, config)

        middleware(req, res, next)
        await new Promise(resolve => req.on("end", resolve))

        expect(req.body).toEqual(data)
        expect(req.rawBody).toBe(payload)
        expect(res.status).not.toHaveBeenCalled()
        expect(res.send).not.toHaveBeenCalled()
        expect(next).toHaveBeenCalledOnce()
    })
})