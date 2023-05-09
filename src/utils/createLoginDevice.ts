import useragent from 'express-useragent';
import prisma from './prisma';
import { getUniqueKey } from './prisma';
import { UAParser } from 'ua-parser-js';

export async function createLoginDevice(ip: string, headers: string, userId: string) {
    const parser = new UAParser(headers);

    const parsedHeaders = parser.getResult();

    const data = await prisma.trackedDevices.findFirst({
        where: {
            ip,
            device: parsedHeaders.device.type ? parsedHeaders.device.type : 'desktop',
            os_name: parsedHeaders.os.name,
            os_version: parsedHeaders.os.version,
            userId,
        },
    });

    if (data) {
        await prisma.trackedDevices.update({
            where: {
                id: data.id,
            },
            data: { updatedAt: new Date() },
        });
    } else
        await prisma.trackedDevices.create({
            data: {
                id: await getUniqueKey(prisma.trackedDevices, 'id'),
                ip,
                device: parsedHeaders.device.type ? parsedHeaders.device.type : 'desktop',
                os_name: parsedHeaders.os.name,
                os_version: parsedHeaders.os.version,
                userId,
            },
        });
}
