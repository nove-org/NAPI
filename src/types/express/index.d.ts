import { OAuth_Authorization, User } from '@prisma/client';

declare global {
    namespace Express {
        interface Request {
            user: Partial<User, 'token'>;
            oauth: OAuth_Authorization;
        }
    }
}
