import checkEnv from "./utils/env";
checkEnv();
import express from "express";
import logger from "./utils/logger";

const app = express();
app.use(express.json());

const server = app.listen(process.env.PORT, () => {
  logger.info("hi");
});
// TODO: add some nice logging (winston or maybe custom?)
process.on("SIGTERM", () => {
  console.log("closing all open socket connections...");
  server.close(() => {
    console.log("server closed");
    process.exit(0x0003);
  });
});
