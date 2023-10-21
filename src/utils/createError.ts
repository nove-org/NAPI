// SOURCE: https://github.com/JuzioMiecio520/CaT/blob/main/server/src/utils/createError.ts

import { Response } from 'express';

export type HTTPStatus =
    | 400 // Bad Request
    | 401 // Unauthorized
    | 402 // Payment Required
    | 403 // Forbidden
    | 404 // Not Found
    | 405 // Method Not Allowed
    | 406 // Not Acceptable
    | 407 // Proxy Authentication Required
    | 408 // Request Timeout
    | 409 // Conflict
    | 410 // Gone
    | 411 // Length Required
    | 412 // Precondition Failed
    | 413 // Payload Too Large
    | 414 // URI Too Long
    | 415 // Unsupported Media Type
    | 416 // Range Not Satisfiable
    | 417 // Expectation Failed
    | 418 // I'm a teapot
    | 421 // Misdirected Request
    | 422 // Unprocessable Entity
    | 423 // Locked
    | 424 // Failed Dependency
    | 425 // Too Early
    | 426 // Upgrade Required
    | 428 // Precondition Required
    | 429 // Too Many Requests
    | 431 // Request Header Fields Too Large
    | 451 // Unavailable For Legal Reasons
    | 500 // Internal Server Error
    | 501 // Not Implemented
    | 502 // Bad Gateway
    | 503 // Service Unavailable
    | 504 // Gateway Timeout
    | 505 // HTTP Version Not Supported
    | 506 // Variant Also Negotiates
    | 507 // Insufficient Storage
    | 508 // Loop Detected
    | 510 // Not Extended
    | 511; // Network Authentication Required

export interface HTTPErrorBody {
    code: string;
    message: string;
    param?: string;
    type: string;
    details?: any;
}

export default function createError(res: Response, status: HTTPStatus, error: HTTPErrorBody) {
    res.status(status).send({
        status: status,
        body: {
            error: {
                code: error.code,
                doc_url: `https://VERYREALURL.DOESNTEXIST/docs/api/errors/${error.type}#${error.code}`,
                message: error.message,
                param: error.param || null,
                type: error.type,
                details: error.details || null,
            },
        },
        meta: {
            timestamp: new Date().toISOString(),
            version: process.env.VERSION,
            server: process.env.SERVER,
        },
    });
}
