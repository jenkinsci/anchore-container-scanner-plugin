package com.anchore.jenkins.plugins.anchore;

import hudson.AbortException;
import java.io.PrintStream;
import java.util.Date;
import java.util.logging.Logger;

public class ConsoleLog {

  private static final Logger LOG = Logger.getLogger(ConsoleLog.class.getName());
  private static final String LOG_FORMAT = "%1$tY-%1$tm-%1$tdT%1$tH:%1$tM:%1$tS.%1$tL %2$-6s %3$-15s %4$s";

  private String name;
  private PrintStream logger;
  private boolean enableDebug;

  public PrintStream getLogger() {
    return logger;
  }

  public boolean isEnableDebug() {
    return enableDebug;
  }

  public ConsoleLog(String name, PrintStream logger, boolean enableDebug) throws AbortException {
    if (null != logger) {
      this.name = name;
      this.logger = logger;
      this.enableDebug = enableDebug;
    } else {
      LOG.warning("Cannot instantiate console logger");
      throw new AbortException("Cannot instantiate console logger");
    }
  }

  public void logDebug(String msg) {
    if (enableDebug) {
      logger.println(String.format(LOG_FORMAT, new Date(), "DEBUG", name, msg));
    }
  }

  public void logDebug(String msg, Throwable t) {
    logDebug(msg);
    if (null != t) {
      t.printStackTrace(logger);
    }
  }

  public void logInfo(String msg) {
    logger.println(String.format(LOG_FORMAT, new Date(), "INFO", name, msg));
  }

  public void logWarn(String msg) {
    logger.println(String.format(LOG_FORMAT, new Date(), "WARN", name, msg));
  }

  public void logWarn(String msg, Throwable t) {
    logWarn(msg);
    if (null != t) {
      t.printStackTrace(logger);
    }
  }

  public void logError(String msg) {
    logger.println(String.format(LOG_FORMAT, new Date(), "ERROR", name, msg));
  }

  public void logError(String msg, Throwable t) {
    logError(msg);
    if (null != t) {
      t.printStackTrace(logger);
    }
  }
}
