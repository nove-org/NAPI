import { OAuth_Authorization, User } from '@prisma/client';
import { TPermission } from '@util/permissions';
import { Modify } from '@util/types';

declare global {
    namespace Express {
        interface Request {
            user: Partial<User, 'token'>;
            oauth: Modify<OAuth_Authorization, { scopes: TPermission[] }>;
        }
    }
}
