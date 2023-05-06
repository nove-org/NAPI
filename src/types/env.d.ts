import { LogLevel } from '../utils/logger';

export type Env = 'development' | 'production';

declare global {
    namespace NodeJS {
        interface ProcessEnv {
            ENV: Env;
            PORT: number;
            LOG_FILES_DIR: string;
            ENABLE_LOG_FILES: boolean;
            FILE_LOG_LEVEL: LogLevel;
            CONSOLE_LOG_LEVEL: LogLevel;
            EXPLICIT_DISABLE_CONSOLE_LOG: boolean;
            JWT_SECRET: string;
        }
    }
}
