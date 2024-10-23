// SOURCE: https://github.com/JuzioMiecio520/CaT/blob/main/server/src/utils/createResponse.ts

import { execSync } from 'child_process';
import { Response } from 'express';
import { SOURCE_CODE } from './CONSTS';
import { StringSchema } from 'yup';

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
    const modifiedSource = process.env.MODIFIED_SOURCE;
    let meta: { timestamp: string; version: string; server: string; source: string; modifiedSource?: string } = {
        timestamp: new Date().toISOString(),
        version: process.env.VERSION + '-' + execSync('git rev-parse --short HEAD').toString().trim(),
        server: process.env.SERVER,
        source: SOURCE_CODE,
    };
    if (modifiedSource)
        meta = {
            ...meta,
            modifiedSource,
        };

    res.status(status).send({
        status: status,
        body: {
            error: null,
            data: body,
        },
        meta,
    });
}
