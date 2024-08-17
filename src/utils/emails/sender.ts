import { User } from '@prisma/client';
import logger from '@util/logger';
import nodemailer from 'nodemailer';
import parseEmail from './parser';

export default async function emailSender({
    user,
    subject,
    file,
    emailOverride,
}: {
    user: User;
    subject: string;
    file: { name: string; pubkey: boolean; vars?: object };
    emailOverride?: string;
}): Promise<boolean> {
    try {
        const transporter = nodemailer.createTransport({
            host: process.env.MAIL_HOST,
            port: 465,
            tls: {
                rejectUnauthorized: false,
            },
            auth: {
                user: process.env.MAIL_USERNAME,
                pass: process.env.MAIL_PASSWORD,
            },
        });

        await transporter.sendMail({
            from: {
                name: 'Nove Account',
                address: process.env.MAIL_USERNAME,
            },
            to: emailOverride || user.email,
            subject,
            text: await parseEmail(file.name, file.pubkey ? user.pubkey : undefined, file.vars),
        });
    } catch {
        logger.error('something went wrong while sending an email for ' + user.id);
        return false;
    }

    return true;
}
