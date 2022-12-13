import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
export default prisma;

export function getUniqueKey(model: any, key: string, generator?: () => string): Promise<string> {
    return new Promise(async (resolve, reject) => {
        let unique = false;
        let value = '';
        while (!unique) {
            value = generator ? generator() : Math.random().toString(36).substring(2, 15);
            const result = await model.findFirst({
                where: {
                    [key]: value,
                },
            });
            if (!result) unique = true;
        }
        resolve(value);
    });
}
