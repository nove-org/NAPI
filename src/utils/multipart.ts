import { NextFunction, Request, Response } from 'express';
import { existsSync, lstatSync, mkdirSync, unlinkSync, writeFileSync } from 'fs';
import multer from 'multer';
import { join } from 'path';
import { STORAGE_PATH } from './CONSTS';
import { move } from 'fs-extra';
import createError from './createError';
import exec from './exec';

export const UPLOADS_TEMP_PATH = '/tmp/NAPI/avatars';

if (!existsSync(UPLOADS_TEMP_PATH)) {
    if (!existsSync(join(UPLOADS_TEMP_PATH, '..'))) mkdirSync(join(UPLOADS_TEMP_PATH, '..'));
    mkdirSync(UPLOADS_TEMP_PATH);
}
if (!lstatSync(UPLOADS_TEMP_PATH).isDirectory()) {
    unlinkSync(UPLOADS_TEMP_PATH);
    mkdirSync(UPLOADS_TEMP_PATH);
}

const storage = multer.diskStorage({
    destination: function (_req, _file, cb) {
        cb(null, UPLOADS_TEMP_PATH);
    },
    filename: function (req, file, cb) {
        cb(null, '1234');
    },
});

export const multerUpload = multer({ storage });
export const multerUploadSingle = (fieldName: string = 'file') => {
    return (req: Request, res: Response, next: NextFunction) => {
        multerUpload.single(fieldName)(req, res, (err) => {
            if (err instanceof multer.MulterError) {
                return createError(res, 500, {
                    code: 'upload_system_error',
                    message: 'An error occurred while uploading the file',
                    param: 'param:file',
                    type: 'internal_error',
                    details: err.message,
                });
            } else if (err) {
                return createError(res, 500, {
                    code: 'upload_system_error',
                    message: 'An error occurred while uploading the file',
                    param: 'param:file',
                    type: 'internal_error',
                    details: err.message,
                });
            }

            exec(`cd ${UPLOADS_TEMP_PATH} && convert 1234 -resize 1024x1024\! 1234.webp`)
                .then(() => {
                    unlinkSync(`${UPLOADS_TEMP_PATH}/1234`);
                    move(`${UPLOADS_TEMP_PATH}/1234.webp`, join(STORAGE_PATH, `1234.webp`), { overwrite: true });
                })
                .catch((err) => {
                    console.log(err);
                    if (err) return createError(res, 500, { code: 'Server error', message: 'An error occurred while procesing the photo.', type: 'internal' });
                });

            next();
        });
    };
};
