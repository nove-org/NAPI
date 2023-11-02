import cors from 'cors';
import express, { Request, Response } from 'express';
import { Server } from 'http';
import createError from '@util/createError';
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
app.set('trust proxy', true);
app.use('/', routes);
app.get('/', (_req: Request, res: Response) => {
    res.json({
        status: 200,
        body: {
            error: null,
            message: 'For more information on how to use the API place check proper documentation (https://git.nove.team/nove-org/NAPI/wiki)',
        },
        meta: {
            timestamp: new Date().toISOString(),
            version: process.env.VERSION,
            server: process.env.SERVER,
        },
    });
});

app.use((_req, res, _next) => {
    return createError(res, 404, { code: 'not_found', message: 'this page does not exist', type: 'authorization' });
});

prisma
    .$connect()
    .then(() => {
        logger.info(`connected to database`);
        const server = app.listen(process.env.PORT, () => {
            logger.info(`server started on port ${process.env.PORT}`);
        });

        process.once('SIGTERM', () => shutdown(server));
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
