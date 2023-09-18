package com.anchore.jenkins.plugins.anchore;

import com.google.common.base.Splitter;
import java.util.regex.Pattern;

public class Util {

  // This is probably the slowest way of formatting strings, should do for now but please figure out a better way
  public static final Splitter IMAGE_LIST_SPLITTER = Splitter.on(Pattern.compile("\\s+")).trimResults().omitEmptyStrings();

  public enum GATE_ACTION {STOP, WARN, GO, PASS, FAIL}

  public enum LOG_LEVEL {DEBUG, WARN, INFO, ERROR}

  public enum GATE_SUMMARY_COLUMN {Repo_Tag, Stop_Actions, Warn_Actions, Go_Actions, Final_Action}

  public enum API_VERSION {v1, v2}

  public static final API_VERSION GET_API_VERSION_FROM_URL(String engineUrl) {
    if (engineUrl.endsWith("v2") || engineUrl.endsWith("v2/")){
      return API_VERSION.v2;
    }
    return API_VERSION.v1;
  }

  public static final String GET_VERSION_KEY(API_VERSION apiVersion, String key) {
    switch(key) {
      case "autosubscribe":
        switch(apiVersion) {
          case v1:
            return "autosubscribe";
          case v2:
            return "auto_subscribe";
        }
        break;
      case "imageDigest":
        switch(apiVersion) {
          case v1:
            return "imageDigest";
          case v2:
            return "image_digest";
        }
        break;
      case "policyId":
        switch(apiVersion) {
          case v1:
            return "policyId";
          case v2:
            return "policy_id";
        }
        break;
    }
    return key;
  }
}
