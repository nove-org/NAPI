import cors from 'cors';
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
app.set('trust proxy', true);
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

        prisma.user.findFirst({ where: { username: 'dawid' } }).then(console.log);

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
