package com.anchore.jenkins.plugins.anchore;


import java.util.List;
import com.google.common.base.Strings;

/**
 * Holder for all Anchore configuration - includes global and project level attributes. A convenience class for capturing a snapshot of
 * the config at the beginning of plugin execution and caching it for use during that specific execution
 */
public class BuildConfig {

  // Build configuration
  private String name;
  private String policyName;
  private String globalWhiteList;
  private String anchoreioUser;
  private String anchoreioPass;
  private String userScripts;
  private String engineRetries;
  private boolean bailOnFail;
  private boolean bailOnWarn;
  private boolean bailOnPluginFail;
  private boolean doCleanup;
  private boolean useCachedBundle;
  private String policyEvalMethod;
  private String bundleFileOverride;
  private List<AnchoreQuery> inputQueries;
  private String policyBundleId;

  // Global configuration
  private boolean debug;
  private String enginemode;
  private String engineurl;
  private String engineuser;
  private String enginepass;
  private boolean engineverify;
  private String containerImageId;
  private String containerId;
  private String localVol;
  private String modulesVol;
  private boolean useSudo;

  public BuildConfig(String name, String policyName, String globalWhiteList, String anchoreioUser, String anchoreioPass,
      String userScripts, String engineRetries, boolean bailOnFail, boolean bailOnWarn, boolean bailOnPluginFail, boolean doCleanup,
      boolean useCachedBundle, String policyEvalMethod, String bundleFileOverride, List<AnchoreQuery> inputQueries,
      String policyBundleId, boolean debug, String enginemode, String engineurl, String engineuser, String enginepass,
      boolean engineverify, String containerImageId, String containerId, String localVol, String modulesVol, boolean useSudo) {
    this.name = name;
    this.policyName = policyName;
    this.globalWhiteList = globalWhiteList;
    this.anchoreioUser = anchoreioUser;
    this.anchoreioPass = anchoreioPass;
    this.userScripts = userScripts;
    this.engineRetries = engineRetries;
    this.bailOnFail = bailOnFail;
    this.bailOnWarn = bailOnWarn;
    this.bailOnPluginFail = bailOnPluginFail;
    this.doCleanup = doCleanup;
    this.useCachedBundle = useCachedBundle;
    this.policyEvalMethod = policyEvalMethod;
    this.bundleFileOverride = bundleFileOverride;
    this.inputQueries = inputQueries;
    this.policyBundleId = policyBundleId;
    this.debug = debug;
    this.enginemode = enginemode;
    this.engineurl = engineurl;
    this.engineuser = engineuser;
    this.enginepass = enginepass;
    this.engineverify = engineverify;
    this.containerImageId = containerImageId;
    this.containerId = containerId;
    this.localVol = localVol;
    this.modulesVol = modulesVol;
    this.useSudo = useSudo;

    if (Strings.isNullOrEmpty(this.enginemode)) {
      this.enginemode = "anchoreengine";
    }
  }

  public String getName() {
    return name;
  }

  public String getPolicyName() {
    return policyName;
  }

  public String getGlobalWhiteList() {
    return globalWhiteList;
  }

  public String getAnchoreioUser() {
    return anchoreioUser;
  }

  public String getAnchoreioPass() {
    return anchoreioPass;
  }

  public String getUserScripts() {
    return userScripts;
  }

  public String getEngineRetries() {
    return engineRetries;
  }

  public boolean getBailOnFail() {
    return bailOnFail;
  }

  public boolean getBailOnWarn() {
    return bailOnWarn;
  }

  public boolean getBailOnPluginFail() {
    return bailOnPluginFail;
  }

  public boolean getDoCleanup() {
    return doCleanup;
  }

  public boolean getUseCachedBundle() {
    return useCachedBundle;
  }

  public String getPolicyEvalMethod() {
    return policyEvalMethod;
  }

  public String getBundleFileOverride() {
    return bundleFileOverride;
  }

  public List<AnchoreQuery> getInputQueries() {
    return inputQueries;
  }

  public String getPolicyBundleId() {
    return policyBundleId;
  }

  public boolean getDebug() {
    return debug;
  }

  public String getEnginemode() {
    return enginemode;
  }

  public boolean isMode(String inmode) {
    if (!Strings.isNullOrEmpty(inmode) && getEnginemode().equals(inmode)) {
      return true;
    }
    return false;
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

  public boolean getEngineverify() {
    return engineverify;
  }

  public String getContainerImageId() {
    return containerImageId;
  }

  public String getContainerId() {
    return containerId;
  }

  public String getLocalVol() {
    return localVol;
  }

  public String getModulesVol() {
    return modulesVol;
  }

  public boolean getUseSudo() {
    return useSudo;
  }

  public void print(ConsoleLog consoleLog) {
    consoleLog.logInfo("[global] debug: " + String.valueOf(debug));
    consoleLog.logInfo("[global] enginemode: " + enginemode);

    if (enginemode.equals("anchoreengine")) {
      // Global properties
      consoleLog.logInfo("[global] engineurl: " + engineurl);
      consoleLog.logInfo("[global] engineuser: " + engineuser);
      consoleLog.logInfo("[global] enginepass: " + "****");
      consoleLog.logInfo("[global] engineverify: " + String.valueOf(engineverify));

      // Build properties
      consoleLog.logInfo("[build] name: " + name);
      consoleLog.logInfo("[build] engineRetries: " + engineRetries);
      consoleLog.logInfo("[build] policyBundleId: " + policyBundleId);
      consoleLog.logInfo("[build] bailOnFail: " + bailOnFail);
      consoleLog.logInfo("[build] bailOnPluginFail: " + bailOnPluginFail);
    } else {
      // Global properties
      consoleLog.logInfo("[global] containerImageId: " + containerImageId);
      consoleLog.logInfo("[global] containerId: " + containerId);
      consoleLog.logInfo("[global] localVol: " + localVol);
      consoleLog.logInfo("[global] modulesVol: " + modulesVol);
      consoleLog.logInfo("[global] useSudo: " + String.valueOf(useSudo));

      // Build properties
      consoleLog.logInfo("[build] name: " + name);
      consoleLog.logInfo("[build] userScripts: " + userScripts);
      consoleLog.logInfo("[build] policyEvalMethod: " + policyEvalMethod);
      if (policyEvalMethod.equals("autosync")) {
        consoleLog.logInfo("[build] anchoreioUser: " + anchoreioUser);
        consoleLog.logInfo("[build] anchoreioPass: " + "****");
        consoleLog.logInfo("[build] useCachedBundle: " + useCachedBundle);
      } else if (policyEvalMethod.equals("bundlefile")) {
        consoleLog.logInfo("[build] bundleFileOverride: " + bundleFileOverride);
      } else if (policyEvalMethod.equals("plainfile")) {
        consoleLog.logInfo("[build] policyName: " + policyName);
        consoleLog.logInfo("[build] globalWhiteList: " + globalWhiteList);
      }
      if (null != inputQueries && !inputQueries.isEmpty()) {
        for (AnchoreQuery anchoreQuery : inputQueries) {
          consoleLog.logInfo("[build] query: " + anchoreQuery.getQuery());
        }
      }
      consoleLog.logInfo("[build] doCleanup: " + doCleanup);
      consoleLog.logInfo("[build] bailOnFail: " + bailOnFail);
      consoleLog.logInfo("[build] bailOnWarn: " + bailOnWarn);
      consoleLog.logInfo("[build] bailOnPluginFail: " + bailOnPluginFail);
    }
  }
}
