// SOURCE: https://github.com/JuzioMiecio520/CaT/blob/main/server/src/utils/schema.ts

import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import createError from './createError';

export const DEFAULT_SCHEMA_OPTIONS: {
    errorMap?: z.ZodErrorMap;
    invalid_type_error?: string;
    required_error?: string;
    description?: string;
} = {
    invalid_type_error: 'invalid type',
    required_error: 'required',
    description: 'Visit documentation for more details',
};

export function validate(
    schema: z.ZodObject<{}, 'strip', z.ZodTypeAny, {}, {}>,
    validate: 'body' | 'query' | 'params' = 'body'
): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
        const parsed = schema.safeParse(req[validate]);

        if (parsed.success) {
            req[validate] = parsed.data;
            next();
        } else {
            createError(res, 400, {
                code: 'invalid_request',
                message: 'Invalid request',
                type: 'validation',
                details: (parsed as any).error.errors,
            });
        }
    };
}
