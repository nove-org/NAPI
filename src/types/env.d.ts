import { LogLevel } from '@util/logger';

export type Env = 'development' | 'production';

declare global {
    namespace NodeJS {
        interface ProcessEnv {
            PORT: number;
            NAPI_URL: string;
            FRONTEND_URL: string;
            MAIL_USERNAME: string;
            MAIL_PASSWORD: string;
            MAIL_HOST: string;
            ENV: Env;
            LOG_FILES_DIR: string;
            ENABLE_LOG_FILES: boolean;
            FILE_LOG_LEVEL: LogLevel;
            CONSOLE_LOG_LEVEL: LogLevel;
            EXPLICIT_DISABLE_CONSOLE_LOG: boolean;
            VERSION: string;
            SERVER: string;
        }
    }
}
