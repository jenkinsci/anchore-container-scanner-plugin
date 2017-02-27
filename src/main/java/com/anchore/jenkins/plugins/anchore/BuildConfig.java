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
  private String userScripts;
  private boolean bailOnFail;
  private boolean bailOnWarn;
  private boolean bailOnPluginFail;
  private boolean doCleanup;
  private List<AnchoreQuery> inputQueries;

  // Global configuration
  private boolean debug;
  private boolean enabled;
  private String containerImageId;
  private String containerId;
  private String localVol;
  private String modulesVol;
  private boolean useSudo;

  public BuildConfig(String name, String policyName, String userScripts, boolean bailOnFail, boolean bailOnWarn,
      boolean bailOnPluginFail, boolean doCleanup, List<AnchoreQuery> inputQueries, boolean debug, boolean enabled,
      String containerImageId, String containerId, String localVol, String modulesVol, boolean useSudo) {
    this.name = name;
    this.policyName = policyName;
    this.userScripts = userScripts;
    this.bailOnFail = bailOnFail;
    this.bailOnWarn = bailOnWarn;
    this.bailOnPluginFail = bailOnPluginFail;
    this.doCleanup = doCleanup;
    this.inputQueries = inputQueries;
    this.debug = debug;
    this.enabled = enabled;
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

  public String getUserScripts() {
    return userScripts;
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

  public List<AnchoreQuery> getInputQueries() {
    return inputQueries;
  }

  public boolean getDebug() {
    return debug;
  }

  public boolean getEnabled() {
    return enabled;
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
    consoleLog.logInfo("[global] debug: " + String.valueOf(debug));
    consoleLog.logInfo("[global] useSudo: " + String.valueOf(useSudo));
    consoleLog.logInfo("[global] containerImageId: " + containerImageId);
    consoleLog.logInfo("[global] containerId: " + containerId);
    consoleLog.logInfo("[global] localVol: " + localVol);
    consoleLog.logInfo("[global] modulesVol: " + modulesVol);

    consoleLog.logInfo("[build] name: " + name);
    consoleLog.logInfo("[build] policyName: " + policyName);
    consoleLog.logInfo("[build] userScripts: " + userScripts);
    consoleLog.logInfo("[build] bailOnFail: " + bailOnFail);
    consoleLog.logInfo("[build] bailOnWarn: " + bailOnWarn);
    consoleLog.logInfo("[build] bailOnPluginFail: " + bailOnPluginFail);
    consoleLog.logInfo("[build] doCleanup: " + doCleanup);
    if (null != inputQueries && !inputQueries.isEmpty()) {
      for (AnchoreQuery anchoreQuery : inputQueries) {
        consoleLog.logInfo("[build] query: " + anchoreQuery.getQuery());
      }
    }
  }
}
