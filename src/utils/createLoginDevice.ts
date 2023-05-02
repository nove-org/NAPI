import useragent from 'express-useragent';
import prisma from './prisma';
import { getUniqueKey } from './prisma';

export async function createLoginDevice(ip: string, headers: string, userId: string) {
    const parsedHeaders = useragent.parse(headers);

    const data = await prisma.devices.findFirst({
        where: {
            ip,
            device: parsedHeaders.isDesktop ? 'desktop' : 'mobile',
            system: parsedHeaders.os,
            userId,
        },
    });

    if (data) {
        await prisma.devices.update({
            where: {
                id: data.id,
            },
            data: { updatedAt: new Date() },
        });
    } else
        await prisma.devices.create({
            data: {
                id: await getUniqueKey(prisma.devices, 'id'),
                ip,
                device: parsedHeaders.isDesktop ? 'desktop' : 'mobile',
                system: parsedHeaders.os,
                userId,
            },
        });
}
