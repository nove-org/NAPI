import express from "express";
import checkEnv from "./utils/env";
import logger from "./utils/logger";
checkEnv();

const app = express();
app.use(express.json());

const server = app.listen(process.env.PORT, () => {
  logger.info(`server started on port ${process.env.PORT}`);
});

function shutdown() {
  logger.info(`closing all open socket connections...`);
  server.close(() => {
    logger.info(`server closed`);
    process.exit(0x0003);
  });
}
process.once("SIGTERM", () => shutdown());
process.once("SIGINT", () => shutdown());
