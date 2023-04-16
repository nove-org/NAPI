import { OAuth_Authorization, User } from '@prisma/client';
import { TPermission } from '../../utils/permissions';
import { Modify } from '../../utils/types';

declare global {
    namespace Express {
        interface Request {
            user: Partial<User, 'token'>;
            oauth: Modify<OAuth_Authorization, { scopes: TPermission[] }>;
        }
    }
}
