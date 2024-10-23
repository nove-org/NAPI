/* 
 NAPI
 Copyright (C) 2019 Nove Group

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>. */

import cors from 'cors';
import express, { Request, Response } from 'express';
import { Server } from 'http';
import createError from '@util/createError';
import routes from './routes';
import checkEnv from './utils/env';
import logger from './utils/logger';
import prisma from './utils/prisma';
import { execSync } from 'child_process';
import { SOURCE_CODE } from '@util/CONSTS';
checkEnv();

const app = express();
app.use(express.json());
app.use(
    cors({
        origin: '*',
    }),
);
app.use(express.static('src/static'));
app.set('view engine', 'ejs');
app.set('views', 'src/views');
app.set('trust proxy', true);
app.use('/', routes);

const modifiedSource = process.env.MODIFIED_SOURCE;
let meta: { timestamp: string; version: string; server: string; source: string; modifiedSource?: string } = {
    timestamp: new Date().toISOString(),
    version: process.env.VERSION + '-' + execSync('git rev-parse --short HEAD').toString().trim(),
    server: process.env.SERVER,
    source: SOURCE_CODE,
};
if (modifiedSource)
    meta = {
        ...meta,
        modifiedSource,
    };

app.get('/', (_req: Request, res: Response) => {
    res.json({
        status: 200,
        body: {
            error: null,
            message: 'For more information on how to use the API place check proper documentation (https://git.nove.team/nove-org/NAPI/wiki)',
        },
        meta,
    });
});

app.use((_req, res, _next) => {
    return createError(res, 404, { code: 'not_found', message: 'This page does not exist', type: 'client_error' });
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
