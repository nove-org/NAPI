import * as yup from 'yup';

require('dotenv').config();

const schema = yup.object({
  PORT: yup.number().required().min(0).max(65535),
  ENV: yup.string().required().matches(/(development|production)/)
});

yup
  .validate(process.env)
  .catch(() => {
    console.error('[CRTITICAL] invalid .env file structure, check README.md for more info');
    console.error(err.errors);
    process.exit(0x0004);
  });
