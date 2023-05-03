import cors from 'cors';
import bcrypt from 'bcrypt';
import express, { Request, Response } from 'express';
import { Server } from 'http';
import routes from './routes';
import checkEnv from './utils/env';
import logger from './utils/logger';
import prisma from './utils/prisma';
checkEnv();

const app = express();
app.use(express.json());
app.use(
    cors({
        origin: '*',
    })
);
app.use(express.static('src/static'));
app.set('view engine', 'ejs');
app.set('views', 'src/views');
app.use('/', routes);
app.get('/', (req: Request, res: Response) => {
    res.json({
        status: 200,
        body: {
            error: null,
            message: 'oh hi there',
        },
        meta: {
            timestamp: new Date().toISOString(),
            version: 'a1.0.0',
            server: 'nove_dev1',
        },
    });
});

prisma
    .$connect()
    .then(() => {
        logger.info(`connected to database`);
        const server = app.listen(process.env.PORT, () => {
            logger.info(`server started on port ${process.env.PORT}`);
        });
        process.once('SIGTERM', () => shutdown(server));

        // prisma.oAuth_App
        //     .create({
        //         data: {
        //             client_id: '6b01162a-5bad-4a02-b97c-0889c8b3db47',
        //             client_secret: 'J8KaEnenvoiPe8eNQ89KCf8LZ5LIBX8SsuaaEXVDY2Hl1vU9c18URxhuI6mPVVhr',
        //             name: 'cheems.dog',
        //             description: 'cheems.dog is a revolutionary image sharing platform',
        //             link_homepage: 'https://cheems.dog',
        //             owner: 'Nove Group',
        //             link_privacy_policy: 'https://cheems.dog/privacy',
        //             link_tos: 'https://cheems.dog/tos',
        //             redirect_uris: ['https://cheems.dog/auth/callback', 'http://localhost:3000/callback.html', 'http://localhost:7100/v1/oauth2/callback'],
        //             isVerified: true,
        //         },
        //     })
        //     .then(console.log)
        //     .catch(console.error);

        // prisma.user
        //     .create({
        //         data: {
        //             id: '01234567',
        //             email: 'user@nove.team',
        //             bio: 'Bio',
        //             language: 'en',
        //             password: bcrypt.hashSync('PASSWORD', bcrypt.genSaltSync()),
        //             token: 'token',
        //             username: 'user',
        //         },
        //     })
        //     .then(console.log)
        //     .catch(console.error);
    })
    .catch((err: Error) => {
        logger.error(`failed to connect to database: ${err}`);
        process.exit(0x000a);
    });

function shutdown(server: Server) {
    logger.info(`closing all open socket connections...`);
    server.close(() => {
        logger.info(`server closed, disconnecting from database...`);
        prisma
            .$disconnect()
            .then(() => {
                logger.info(`disconnected from database`);
                process.exit(0x0003);
            })
            .catch((err: Error) => {
                logger.error(`failed to gracefully disconnect from database: ${err}`);
                process.exit(0x000a);
            });
    });
}
