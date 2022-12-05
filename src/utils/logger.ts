import { readFileSync, writeFileSync } from "fs";
import { Env } from "../types/env";
import path from "path";
import chalk from "chalk";

export type LogLevel =
  | "silly"
  | "debug"
  | "info"
  | "warn"
  | "error"
  | "critical";

export class Logger {
  private file: string;
  private logsPath = path.join(__dirname, "..", process.env.LOG_FILES_DIR);
  private fileWriteCache: string = "";

  public constructor() {
    const date = new Date();
    this.file = path.join(
      this.logsPath,
      `${date.getFullYear()}-${(date.getMonth() + 1)
        .toString()
        .padStart(2, "0")}-${date.getDate().toString().padStart(2, "0")}_${date
        .getHours()
        .toString()
        .padStart(2, "0")}-${date
        .getMinutes()
        .toString()
        .padStart(2, "0")}-${date.getSeconds().toString().padStart(2, "0")}.log`
    );
    this.fileWriteCache = readFileSync(this.file).toString();
  }

  public silly(...args: any[]) {
    this.log("silly", `${chalk.white.bgMagenta("SILLY")}`, "SILLY", ...args);
  }
  public debug(...args: any[]) {
    this.log(
      "debug",
      `${chalk.white.bgGreenBright("DEBUG")}`,
      "DEBUG",
      ...args
    );
  }
  public info(...args: any[]) {
    this.log("info", `${chalk.white.bgBlue("INFO")}`, "INFO", ...args);
  }
  public warn(...args: any[]) {
    this.log("warn", `${chalk.white.bgYellow("WARN")}`, "WARN", ...args);
  }
  public error(...args: any[]) {
    this.log("error", `${chalk.white.bgRedBright("ERR")}`, "ERR", ...args);
  }
  public critical(...args: any[]) {
    this.log("critical", `${chalk.white.bgRed("CRIT")}`, "CRIT", ...args);
  }

  private log(
    level: LogLevel,
    consolePrefix: string,
    filePrefix: string,
    ...args: any[]
  ) {
    if (
      !process.env.EXPLICIT_DISABLE_CONSOLE_LOG &&
      this.checkLogLevel(level, process.env.CONSOLE_LOG_LEVEL)
    )
      console.log(`${this.formatDate(new Date())} [${consolePrefix}]`, ...args);
    if (
      process.env.ENABLE_LOG_FILES &&
      this.checkLogLevel(level, process.env.FILE_LOG_LEVEL)
    )
      this.logToFile(filePrefix, ...args);
  }

  private checkLogLevel(logLevel: LogLevel, acceptedLevel: LogLevel) {
    return (
      (logLevel === "silly" && acceptedLevel === "silly") ||
      (logLevel === "debug" && ["silly", "debug"].includes(acceptedLevel)) ||
      (logLevel === "info" &&
        ["silly", "debug", "info"].includes(acceptedLevel)) ||
      (logLevel === "warn" &&
        ["silly", "debug", "info", "warn"].includes(acceptedLevel)) ||
      (logLevel === "error" &&
        ["silly", "debug", "info", "warn", "error"].includes(acceptedLevel)) ||
      (logLevel === "critical" &&
        ["silly", "debug", "info", "warn", "error", "critical"].includes(
          acceptedLevel
        ))
    );
  }

  private logToFile(filePrefix: string, ...args: any[]) {
    this.fileWriteCache += `${this.formatDate(
      new Date()
    )} [${filePrefix}] ${args.join(" ")}\n`;
    writeFileSync(this.file, this.fileWriteCache);
  }

  private formatDate(date: Date) {
    return `${date.getFullYear()}-${(date.getMonth() + 1)
      .toString()
      .padStart(2, "0")}-${date.getDate().toString().padStart(2, "0")} ${date
      .getHours()
      .toString()
      .padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}:${date
      .getSeconds()
      .toString()
      .padStart(2, "0")}:${date.getMilliseconds().toString().padStart(4, "0")}`;
  }
}

const logger = new Logger();
export default logger;
