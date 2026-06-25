export enum LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  WARN = 3,
  ERROR = 4,
}

export interface LogContext {
  [key: string]: unknown;
}

export class Logger {
  private level: LogLevel;
  private category: string;

  constructor(category: string, defaultLevel: LogLevel = LogLevel.INFO) {
    this.category = category;
    this.level = this.parseLogLevel(process.env.SDK_LOG_LEVEL) ?? defaultLevel;
  }

  private parseLogLevel(levelStr?: string): LogLevel | undefined {
    if (!levelStr) return undefined;
    const l = levelStr.toUpperCase();
    if (l in LogLevel) return LogLevel[l as keyof typeof LogLevel];
    return undefined;
  }

  public setLevel(level: LogLevel): void {
    this.level = level;
  }

  public trace(message: string, context?: LogContext): void {
    this.log(LogLevel.TRACE, message, context);
  }

  public debug(message: string, context?: LogContext): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  public info(message: string, context?: LogContext): void {
    this.log(LogLevel.INFO, message, context);
  }

  public warn(message: string, context?: LogContext): void {
    this.log(LogLevel.WARN, message, context);
  }

  public error(message: string, error?: Error | unknown, context?: LogContext): void {
    this.log(LogLevel.ERROR, message, {
      ...context,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
  }

  private log(level: LogLevel, message: string, context?: LogContext): void {
    if (level < this.level) return;

    const timestamp = new Date().toISOString();
    const levelName = LogLevel[level];
    
    const logEntry = {
      timestamp,
      level: levelName,
      category: this.category,
      message,
      ...(context && { context }),
    };

    const output = JSON.stringify(logEntry);

    switch (level) {
      case LogLevel.ERROR:
        console.error(output);
        break;
      case LogLevel.WARN:
        console.warn(output);
        break;
      case LogLevel.INFO:
        console.info(output);
        break;
      case LogLevel.DEBUG:
      case LogLevel.TRACE:
      default:
        console.debug(output);
        break;
    }
  }
}
