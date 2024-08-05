package com.anchore.jenkins.plugins.anchore;

import com.google.common.base.Splitter;
import java.util.regex.Pattern;

public class Util {

  // This is probably the slowest way of formatting strings, should do for now but please figure out a better way
  public static final Splitter IMAGE_LIST_SPLITTER = Splitter.on(Pattern.compile("\\s+")).trimResults().omitEmptyStrings();

  public enum GATE_ACTION {STOP, WARN, GO, PASS, FAIL}

  public enum LOG_LEVEL {DEBUG, WARN, INFO, ERROR}

  public enum GATE_SUMMARY_COLUMN {Repo_Tag, Stop_Actions, Warn_Actions, Go_Actions, Final_Action, Stop_Action_Details}

  public enum API_VERSION {v1, v2}

  public static final API_VERSION GET_API_VERSION_FROM_URL(String engineUrl) {
    if (engineUrl.endsWith("v2") || engineUrl.endsWith("v2/")){
      return API_VERSION.v2;
    }
    return API_VERSION.v1;
  }
}
