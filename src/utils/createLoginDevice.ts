import { User } from '@prisma/client';
import prisma from './prisma';
import { getUniqueKey } from './prisma';
import { UAParser } from 'ua-parser-js';
import { decryptWithToken, encryptWithToken } from './tokenEncryption';

export async function createLoginDevice(ip: string, headers: string, user: User) {
    const parser = new UAParser(headers);
    const parsedHeaders = parser.getResult();

    if (!user.trackActivity) return;

    const data = await prisma.trackedDevices
        .findMany({
            where: {
                userId: user.id,
            },
        })
        .catch(console.error);

    const newData = data?.find((dev) => {
        const decryptedDevice = {
            ip: decryptWithToken(dev.ip, user.token),
            device: decryptWithToken(dev.device, user.token),
            os_name: decryptWithToken(dev.os_name, user.token),
            os_version: decryptWithToken(dev.os_version, user.token),
        };

        return (
            decryptedDevice.ip === ip &&
            decryptedDevice.device === (parsedHeaders.device.type ? 'mobile' : 'desktop') &&
            decryptedDevice.os_name === (parsedHeaders.os.name || 'unknown') &&
            decryptedDevice.os_version === (parsedHeaders.os.version || 'unknown')
        );
    });

    if (newData) {
        await prisma.trackedDevices
            .update({
                where: {
                    id: newData.id,
                },
                data: { updatedAt: new Date() },
            })
            .catch(console.error);
    } else
        await prisma.trackedDevices
            .create({
                data: {
                    id: await getUniqueKey(prisma.trackedDevices, 'id'),
                    ip: encryptWithToken(ip, user.token),
                    device: encryptWithToken(parsedHeaders.device.type ? 'mobile' : 'desktop', user.token),
                    os_name: encryptWithToken(parsedHeaders.os.name || 'unknown', user.token),
                    os_version: encryptWithToken(parsedHeaders.os.version || 'unknown', user.token),
                    userId: user.id,
                },
            })
            .catch(console.error);

    const allData = await prisma.trackedDevices.findMany({ where: { userId: user.id } });

    allData.forEach(async (device) => {
        if (device.updatedAt.getTime() + 2629800000 < new Date().getTime()) {
            if (await prisma.trackedDevices.findUnique({ where: { id: device.id } })) await prisma.trackedDevices.delete({ where: { id: device.id } });
        }
    });
}
