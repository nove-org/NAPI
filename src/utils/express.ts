import { Request } from 'express';

export function getFullHrefFromRequest(req: Request): string {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
}
