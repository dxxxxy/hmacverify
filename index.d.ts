import type { Request, Response, NextFunction } from 'express';
import type { BinaryToTextEncoding } from 'crypto';

export interface HmacVerifyOptions {
    /** Header name where the signature is expected (default: "x-shoppy-signature") */
    header?: string;
    /** HMAC algorithm to use (default: "sha512") */
    algorithm?: string;
    /** Encoding of the signature (default: "hex") */
    encoding?: BinaryToTextEncoding;
    /** Maximum payload size in bytes to prevent attacks (default: 10485760 / 10MB) */
    limit?: number;
    /** HTTP status code to send when signature verification fails (default: 401) */
    statusCode?: number;
    /** Message to send when signature verification fails (default: "Invalid signature") */
    message?: string;
}

export default function hmacVerify(
    secret: string,
    options?: HmacVerifyOptions
): (req: Request, res: Response, next: NextFunction) => void;
