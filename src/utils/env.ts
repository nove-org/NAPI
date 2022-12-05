import * as yup from "yup";

require("dotenv").config();

export default function checkEnv() {
  const schema = yup.object({
    PORT: yup.number().required().min(0).max(65535),
    ENV: yup
      .string()
      .required()
      .matches(/(development|production)/),
      LOG_FILES_DIR: yup
        .string()
        .default('logs'),
        ENABLE_LOG_FILES: yup
        .boolean()
        .default(true),
        FILE_LOG_LEVEL: yup
        .string()
        .matches(/(silly|debug|info|warn|error|critical)/)
        .default('warn'),
        CONSOLE_LOG_LEVEL: yup
        .string()
        .matches(/(silly|debug|info|warn|error|critical)/)
        .default('info'),
        EXPLICIT_DISABLE_CONSOLE_LOG: yup.boolean().default(false)
  });
try {
    
    schema.validateSync(process.env);
    process.env = schema.cast(process.env) as any;
    } catch(err:any) {
    console.error(
        "[CRTITICAL] invalid .env file structure, check README.md for more info"
        );
        console.error(err.errors);
        process.exit(0x0004);

    }
}