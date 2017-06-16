package com.anchore.jenkins.plugins.anchore;


import java.util.List;

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
  private String drogueRetries;
  private boolean bailOnFail;
  private boolean bailOnWarn;
  private boolean bailOnPluginFail;
  private boolean doCleanup;
  private boolean useCachedBundle;
  private String policyEvalMethod;
  private String bundleFileOverride;
  private List<AnchoreQuery> inputQueries;

  // Global configuration
  private boolean debug;
  private boolean enabled;
  private boolean droguemode;
  private String drogueurl;
  private String drogueuser;
  private String droguepass;
  private String containerImageId;
  private String containerId;
  private String localVol;
  private String modulesVol;
  private boolean useSudo;

    public BuildConfig(String name, String policyName, String globalWhiteList, String anchoreioUser, String anchoreioPass, String userScripts, String drogueRetries, boolean bailOnFail,
		       boolean bailOnWarn, boolean bailOnPluginFail, boolean doCleanup, boolean useCachedBundle, String policyEvalMethod, String bundleFileOverride, List<AnchoreQuery> inputQueries, boolean debug, boolean enabled, boolean droguemode, String drogueurl, String drogueuser, String droguepass,
		       String containerImageId, String containerId, String localVol, String modulesVol, boolean useSudo) {
    this.name = name;
    this.policyName = policyName;
    this.globalWhiteList = globalWhiteList;
    this.anchoreioUser = anchoreioUser;
    this.anchoreioPass = anchoreioPass;
    this.userScripts = userScripts;
    this.drogueRetries = drogueRetries;
    this.bailOnFail = bailOnFail;
    this.bailOnWarn = bailOnWarn;
    this.bailOnPluginFail = bailOnPluginFail;
    this.doCleanup = doCleanup;
    this.useCachedBundle = useCachedBundle;
    this.policyEvalMethod = policyEvalMethod;
    this.bundleFileOverride = bundleFileOverride;
    this.inputQueries = inputQueries;
    this.debug = debug;
    this.enabled = enabled;
    this.droguemode = droguemode;
    this.drogueurl = drogueurl;
    this.drogueuser = drogueuser;
    this.droguepass = droguepass;
    this.containerImageId = containerImageId;
    this.containerId = containerId;
    this.localVol = localVol;
    this.modulesVol = modulesVol;
    this.useSudo = useSudo;
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

  public String getDrogueRetries() {
    return drogueRetries;
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

  public boolean getDebug() {
    return debug;
  }

  public boolean getEnabled() {
    return enabled;
  }

  public boolean getDroguemode() {
    return droguemode;
  }

  public String getDrogueurl() {
    return drogueurl;
  }

  public String getDrogueuser() {
    return drogueuser;
  }

  public String getDroguepass() {
    return droguepass;
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
    consoleLog.logInfo("[global] enabled: " + String.valueOf(enabled));
    consoleLog.logInfo("[global] droguemode: " + String.valueOf(droguemode));
    consoleLog.logInfo("[global] drogueurl: " + drogueurl);
    consoleLog.logInfo("[global] drogueuser: " + drogueuser);
    consoleLog.logInfo("[global] droguepass: " + "****");
    consoleLog.logInfo("[global] debug: " + String.valueOf(debug));
    consoleLog.logInfo("[global] useSudo: " + String.valueOf(useSudo));
    consoleLog.logInfo("[global] containerImageId: " + containerImageId);
    consoleLog.logInfo("[global] containerId: " + containerId);
    consoleLog.logInfo("[global] localVol: " + localVol);
    consoleLog.logInfo("[global] modulesVol: " + modulesVol);

    consoleLog.logInfo("[build] name: " + name);
    consoleLog.logInfo("[build] policyName: " + policyName);
    consoleLog.logInfo("[build] globalWhiteList: " + globalWhiteList);
    consoleLog.logInfo("[build] anchoreioUser: " + anchoreioUser);
    consoleLog.logInfo("[build] anchoreioPass: " + "****");
    consoleLog.logInfo("[build] userScripts: " + userScripts);
    consoleLog.logInfo("[build] drogueRetries: " + drogueRetries);
    consoleLog.logInfo("[build] bailOnFail: " + bailOnFail);
    consoleLog.logInfo("[build] bailOnWarn: " + bailOnWarn);
    consoleLog.logInfo("[build] bailOnPluginFail: " + bailOnPluginFail);
    consoleLog.logInfo("[build] doCleanup: " + doCleanup);
    consoleLog.logInfo("[build] useCachedBundle: " + useCachedBundle);
    consoleLog.logInfo("[build] policyEvalMethod: " + policyEvalMethod);
    consoleLog.logInfo("[build] bundleFileOverride: " + bundleFileOverride);
    if (null != inputQueries && !inputQueries.isEmpty()) {
      for (AnchoreQuery anchoreQuery : inputQueries) {
        consoleLog.logInfo("[build] query: " + anchoreQuery.getQuery());
      }
    }
  }
}
