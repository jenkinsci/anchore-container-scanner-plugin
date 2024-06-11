package com.anchore.jenkins.plugins.anchore;


import com.anchore.jenkins.plugins.anchore.Util.API_VERSION;
import java.util.List;

/**
 * Holder for all Anchore configuration - includes global and project level attributes. A convenience class for capturing a snapshot of
 * the config at the beginning of plugin execution and caching it for use during that specific execution
 */
public class BuildConfig {

  // Build configuration
  private String name;
  private String engineRetries;
  private boolean bailOnFail;
  private boolean bailOnPluginFail;
  private String policyBundleId;
  private List<Annotation> annotations;
  private boolean autoSubscribeTagUpdates;
  private boolean forceAnalyze;
  private boolean excludeFromBaseImage;

  // Global configuration
  private boolean debug;
  private String engineurl;
  private String engineuser;
  private String enginepass;
  private String engineaccount;
  private boolean engineverify;
  private API_VERSION engineApiVersion;

  public BuildConfig(String name,  String engineRetries, boolean bailOnFail, boolean bailOnPluginFail,
      String policyBundleId, List<Annotation> annotations, boolean autoSubscribeTagUpdates, boolean forceAnalyze, boolean excludeFromBaseImage,
      boolean debug, String engineurl, String engineuser, String enginepass, String engineaccount, boolean engineverify) {
    this.name = name;
    this.engineRetries = engineRetries;
    this.bailOnFail = bailOnFail;
    this.bailOnPluginFail = bailOnPluginFail;
    this.policyBundleId = policyBundleId;
    this.annotations = annotations;
    this.autoSubscribeTagUpdates = autoSubscribeTagUpdates;
    this.forceAnalyze = forceAnalyze;
    this.excludeFromBaseImage = excludeFromBaseImage;
    this.debug = debug;
    this.engineurl = engineurl;
    this.engineuser = engineuser;
    this.enginepass = enginepass;
    this.engineaccount = engineaccount;
    this.engineverify = engineverify;
    this.engineApiVersion = Util.GET_API_VERSION_FROM_URL(engineurl);
  }

  public String getName() {
    return name;
  }

  public String getEngineRetries() {
    return engineRetries;
  }

  public boolean getBailOnFail() {
    return bailOnFail;
  }

  public boolean getBailOnPluginFail() {
    return bailOnPluginFail;
  }

  public String getPolicyBundleId() {
    return policyBundleId;
  }

  public List<Annotation> getAnnotations() {
    return annotations;
  }

  public boolean getAutoSubscribeTagUpdates() {
    return autoSubscribeTagUpdates;
  }

  public boolean getForceAnalyze() {
    return forceAnalyze;
  }

  public boolean getExcludeFromBaseImage() {
    return excludeFromBaseImage;
  }

  public boolean getDebug() {
    return debug;
  }

  public String getEngineurl() {
    return engineurl;
  }

  public String getEngineuser() {
    return engineuser;
  }

  public String getEnginepass() {
    return enginepass;
  }

  public String getEngineaccount() {
    return engineaccount;
  }

  public boolean getEngineverify() {
    return engineverify;
  }

  public API_VERSION getEngineApiVersion() {
    return engineApiVersion;
  }

  public void print(ConsoleLog consoleLog) {
    consoleLog.logInfo("[global] debug: " + String.valueOf(debug));

    // Global or build properties
    consoleLog.logInfo("[build] engineurl: " + engineurl);
    consoleLog.logInfo("[build] engineuser: " + engineuser);
    consoleLog.logInfo("[build] enginepass: " + "****");
    consoleLog.logInfo("[build] engineaccount: " + engineaccount);
    consoleLog.logInfo("[build] engineverify: " + String.valueOf(engineverify));

    // Build properties
    consoleLog.logInfo("[build] name: " + name);
    consoleLog.logInfo("[build] engineRetries: " + engineRetries);
    consoleLog.logInfo("[build] policyBundleId: " + policyBundleId);
    if (null != annotations && !annotations.isEmpty()) {
      for (Annotation a : annotations) {
        consoleLog.logInfo("[build] annotation: " + a.getKey() + "=" + a.getValue());
      }
    }
    consoleLog.logInfo("[build] bailOnFail: " + bailOnFail);
    consoleLog.logInfo("[build] bailOnPluginFail: " + bailOnPluginFail);
  }
}
