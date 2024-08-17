import { User } from '@prisma/client';
import logger from '@util/logger';
import nodemailer from 'nodemailer';
import parseEmail from './parser';

export default async function emailSender({ user, file, emailOverride }: { user: User; file: { name: string; pubkey: boolean; vars?: object }; emailOverride?: string }): Promise<boolean> {
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

        const email = await parseEmail(file.name, user.language, file.pubkey ? user.pubkey : undefined, file.vars);
        await transporter.sendMail({
            from: {
                name: email.name,
                address: process.env.MAIL_USERNAME,
            },
            to: emailOverride || user.email,
            subject: email.subject,
            text: email.text,
        });
    } catch {
        logger.error('something went wrong while sending an email for ' + user.id);
        return false;
    }

    return true;
}
