import express from 'express';
import './utils/env.ts';

const app = express();

app.use(express.json());

// TODO: add some nice logging (winston or maybe custom?)
process.on('SIGTERM', () => {
  console.log('closing all open socket connections...');
  app.close(() => {
    console.log('server closed');
    process.exit(0x0003);
  });
});
app.listen(process.env.PORT, () => {
    console.log('started');
});
