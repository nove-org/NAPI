// SOURCE: https://github.com/JuzioMiecio520/CaT/blob/main/server/src/utils/createResponse.ts

import { Response } from 'express';

export type HTTPStatus =
    | 200 // OK
    | 201 // Created
    | 202 // Accepted
    | 203 // Non-Authoritative Information
    | 204 // No Content
    | 205 // Reset Content
    | 206 // Partial Content
    | 207 // Multi - Status
    | 208 // Already Reported
    | 226; // IM Used

export default function createResponse(res: Response, status: HTTPStatus, body: any) {
    res.status(status).send({
        status: status,
        body: {
            error: null,
            data: body,
        },
        meta: {
            timestamp: new Date().toISOString(),
            version: '0.1.0',
        },
    });
}
