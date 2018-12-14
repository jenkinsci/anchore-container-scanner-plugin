package com.anchore.jenkins.plugins.anchore;


import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * <p>Anchore Plugin enables Jenkins users to scan container images, generate analysis, evaluate gate policy, and execute customizable
 * queries. The plugin can be used in a freestyle project as a step or invoked from a pipeline script</p>
 *
 * <p>Requirements:</p>
 *
 * <ol> <li>Jenkins installed and configured either as a single system, or with multiple configured jenkins worker nodes</li>
 *
 * <li>Each host on which jenkins jobs will run must have docker installed and the jenkins user (or whichever user you have configured
 * jenkins to run jobs as) must be allowed to interact with docker (either directly or via sudo)</li>
 *
 * <li>Each host on which jenkins jobs will run must have the latest anchore container image installed in the local docker host. To
 * install, run 'docker pull anchore/jenkins:latest' on each jenkins host to make the image available to the plugin. The plugin will
 * start an instance of the anchore/jenkins:latest docker container named 'jenkins_anchore' by default, on each host that runs a
 * jenkins job that includes an Anchore Container Image Scanner step.</li> </ol>
 */
public class AnchoreBuilder extends Builder implements SimpleBuildStep {

  //  Log handler for logging above INFO level events to jenkins log
  private static final Logger LOG = Logger.getLogger(AnchoreBuilder.class.getName());

  // Assigning the defaults here for pipeline builds
  private String name;
  private String policyName = DescriptorImpl.DEFAULT_POLICY_NAME;
  private String globalWhiteList = DescriptorImpl.DEFAULT_GLOBAL_WHITELIST;
  private String anchoreioUser = DescriptorImpl.DEFAULT_ANCHORE_IO_USER;
  private String anchoreioPass = DescriptorImpl.DEFAULT_ANCHORE_IO_PASSWORD;
  private String userScripts = DescriptorImpl.DEFAULT_USER_SCRIPTS;
  private String engineRetries = DescriptorImpl.DEFAULT_ENGINE_RETRIES;
  private boolean bailOnFail = DescriptorImpl.DEFAULT_BAIL_ON_FAIL;
  private boolean bailOnWarn = DescriptorImpl.DEFAULT_BAIL_ON_WARN;
  private boolean bailOnPluginFail = DescriptorImpl.DEFAULT_BAIL_ON_PLUGIN_FAIL;
  private boolean doCleanup = DescriptorImpl.DEFAULT_DO_CLEANUP;
  private boolean useCachedBundle = DescriptorImpl.DEFAULT_USE_CACHED_BUNDLE;
  private String policyEvalMethod = DescriptorImpl.DEFAULT_POLICY_EVAL_METHOD;
  private String bundleFileOverride = DescriptorImpl.DEFAULT_BUNDLE_FILE_OVERRIDE;
  private List<AnchoreQuery> inputQueries;
  private String policyBundleId = DescriptorImpl.DEFAULT_POLICY_BUNDLE_ID;
  private double stopActionHealthFactor = DescriptorImpl.DEFAULT_STOP_ACTION_HEALTH_FACTOR;
  private double warnActionHealthFactor = DescriptorImpl.DEFAULT_WARN_ACTION_HEALTH_FACTOR;
  private Integer unstableStopThreshold = DescriptorImpl.DEFAULT_UNSTABLE_STOP_THRESHOLD;
  private Integer unstableWarnThreshold = DescriptorImpl.DEFAULT_UNSTABLE_WARN_THRESHOLD;
  private Integer failedStopThreshold = DescriptorImpl.DEFAULT_FAILED_STOP_THRESHOLD;
  private Integer failedWarnThreshold = DescriptorImpl.DEFAULT_FAILED_WARN_THRESHOLD;
  
  private List<Annotation> annotations;

  // Override global config. Supported for anchore-engine mode config only
  private String engineurl = DescriptorImpl.EMPTY_STRING;
  private String engineCredentialsId = DescriptorImpl.EMPTY_STRING;
  private boolean engineverify = false;
  // More flags to indicate boolean override, ugh!
  private boolean isEngineverifyOverrride = false;

  // Getters are used by config.jelly
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
  
  public double getWarnActionHealthFactor(){
    return warnActionHealthFactor;
  }
  
  public double getStopActionHealthFactor(){
    return stopActionHealthFactor;
  }

  public Integer getUnstableStopThreshold(){
    return unstableStopThreshold;
  }

  public Integer getUnstableWarnThreshold(){
    return unstableWarnThreshold;
  }

  public Integer getFailedStopThreshold(){
    return failedStopThreshold;
  }

  public Integer getFailedWarnThreshold(){
    return failedWarnThreshold;
  }

  public List<Annotation> getAnnotations() {
    return annotations;
  }

  public String getEngineurl() {
    return engineurl;
  }

  public String getEngineCredentialsId() {
    return engineCredentialsId;
  }

  public boolean getEngineverify() {
    return engineverify;
  }

  @DataBoundSetter
  public void setPolicyName(String policyName) {
    this.policyName = policyName;
  }

  @DataBoundSetter
  public void setGlobalWhiteList(String globalWhiteList) {
    this.globalWhiteList = globalWhiteList;
  }

  @DataBoundSetter
  public void setAnchoreioUser(String anchoreioUser) {
    this.anchoreioUser = anchoreioUser;
  }

  @DataBoundSetter
  public void setAnchoreioPass(String anchoreioPass) {
    this.anchoreioPass = anchoreioPass;
  }

  @DataBoundSetter
  public void setUserScripts(String userScripts) {
    this.userScripts = userScripts;
  }

  @DataBoundSetter
  public void setEngineRetries(String engineRetries) {
    this.engineRetries = engineRetries;
  }

  @DataBoundSetter
  public void setBailOnFail(boolean bailOnFail) {
    this.bailOnFail = bailOnFail;
  }

  @DataBoundSetter
  public void setBailOnWarn(boolean bailOnWarn) {
    this.bailOnWarn = bailOnWarn;
  }

  @DataBoundSetter
  public void setBailOnPluginFail(boolean bailOnPluginFail) {
    this.bailOnPluginFail = bailOnPluginFail;
  }

  @DataBoundSetter
  public void setDoCleanup(boolean doCleanup) {
    this.doCleanup = doCleanup;
  }

  @DataBoundSetter
  public void setUseCachedBundle(boolean useCachedBundle) {
    this.useCachedBundle = useCachedBundle;
  }

  @DataBoundSetter
  public void setPolicyEvalMethod(String policyEvalMethod) {
    this.policyEvalMethod = policyEvalMethod;
  }

  @DataBoundSetter
  public void setBundleFileOverride(String bundleFileOverride) {
    this.bundleFileOverride = bundleFileOverride;
  }

  // Convenience method for easily passing queries, invoked only by Jenkins Pipelines
  @DataBoundSetter
  public void setInputQueries(List<AnchoreQuery> inputQueries) {
    this.inputQueries = inputQueries;
  }

  @DataBoundSetter
  public void setPolicyBundleId(String policyBundleId) {
    this.policyBundleId = policyBundleId;
  }

  @DataBoundSetter
  public void setWarnActionHealthFactor(double warnActionHealthFactor){
    this.warnActionHealthFactor = warnActionHealthFactor;
  }

  @DataBoundSetter
  public void setStopActionHealthFactor(double stopActionHealthFactor){
    this.stopActionHealthFactor = stopActionHealthFactor;
  }

  @DataBoundSetter
  public void setUnstableStopThreshold(Integer unstableStopThreshold){
    this.unstableStopThreshold = unstableStopThreshold;
  }

  @DataBoundSetter
  public void setUnstableWarnThreshold(Integer unstableWarnThreshold){
    this.unstableWarnThreshold = unstableWarnThreshold;
  }

  @DataBoundSetter
  public void setFailedStopThreshold(Integer failedStopThreshold){
    this.failedStopThreshold = failedStopThreshold;
  }

  @DataBoundSetter
  public void setFailedWarnThreshold(Integer failedWarnThreshold){
    this.failedWarnThreshold = failedWarnThreshold;
  }

  @DataBoundSetter
  public void setAnnotations(List<Annotation> annotations) {
    this.annotations = annotations;
  }

  @DataBoundSetter
  public void setEngineurl(String engineurl) {
    this.engineurl = engineurl;
  }

  @DataBoundSetter
  public void setEngineCredentialsId(String engineCredentialsId) {
    this.engineCredentialsId = engineCredentialsId;
  }

  @DataBoundSetter
  public void setEngineverify(boolean engineverify) {
    this.engineverify = engineverify;
    this.isEngineverifyOverrride = true;
  }

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor" or "DataBoundSetter"
  @DataBoundConstructor
  public AnchoreBuilder(String name) {
    this.name = name;
  }

  @Override
  public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener)
      throws InterruptedException, IOException {

    LOG.warning(
        "Starting Anchore Container Image Scanner step, project: " + run.getParent().getDisplayName() + ", job: " + run.getNumber());

    BuildConfig config = null;
    BuildWorker worker = null;
    DescriptorImpl globalConfig = getDescriptor();
    ConsoleLog console = new ConsoleLog("AnchorePlugin", listener.getLogger(), globalConfig.getDebug());

    try {

      /* Fetch Jenkins creds first, can't push this lower down the chain since it requires Jenkins instance object */
      String engineuser = null;
      String enginepass = null;
      if (!Strings.isNullOrEmpty(engineCredentialsId)) {
        console.logDebug("Found build override for anchore-engine credentials. Processing Jenkins credential ID ");
        try {
          StandardUsernamePasswordCredentials creds = CredentialsProvider
              .findCredentialById(engineCredentialsId, StandardUsernamePasswordCredentials.class, run,
                  Collections.<DomainRequirement>emptyList());
          if (null != creds) {
            engineuser = creds.getUsername();
            enginepass = creds.getPassword().getPlainText();
          } else {
            throw new AbortException("Cannot find Jenkins credentials by ID: \'" + engineCredentialsId
                + "\'. Ensure credentials are defined in Jenkins before using them");
          }
        } catch (AbortException e) {
          throw e;
        } catch (Exception e) {
          console.logError("Error looking up Jenkins credentials by ID: \'" + engineCredentialsId + "\'", e);
          throw new AbortException("Error looking up Jenkins credentials by ID: \'" + engineCredentialsId);
        }
      }

      /* Instantiate config and a new build worker */
      config = new BuildConfig(name, policyName, globalWhiteList, anchoreioUser, anchoreioPass, userScripts, engineRetries, bailOnFail,
          bailOnWarn, bailOnPluginFail, doCleanup, useCachedBundle, policyEvalMethod, bundleFileOverride, inputQueries, policyBundleId,
          warnActionHealthFactor, stopActionHealthFactor, unstableStopThreshold, unstableWarnThreshold, failedStopThreshold,
          failedWarnThreshold, annotations, globalConfig.getDebug(), globalConfig.getEnginemode(),
          // messy build time overrides, ugh!
          !Strings.isNullOrEmpty(engineurl) ? engineurl : globalConfig.getEngineurl(),
          !Strings.isNullOrEmpty(engineuser) ? engineuser : globalConfig.getEngineuser(),
          !Strings.isNullOrEmpty(enginepass) ? enginepass : globalConfig.getEnginepass().getPlainText(),
          isEngineverifyOverrride ? engineverify : globalConfig.getEngineverify(), globalConfig.getContainerImageId(),
          globalConfig.getContainerId(), globalConfig.getLocalVol(), globalConfig.getModulesVol(), globalConfig.getUseSudo());
      worker = new BuildWorker(run, workspace, launcher, listener, config);

      /* Log any build time overrides are at play */
      if (!Strings.isNullOrEmpty(engineurl)) {
        console.logInfo("Build override set for Anchore Engine URL");
      }
      if (!Strings.isNullOrEmpty(engineuser) && !Strings.isNullOrEmpty(enginepass)) {
        console.logInfo("Build override set for Anchore Engine credentials");
      }
      if (isEngineverifyOverrride) {
        console.logInfo("Build override set for Anchore Engine verify SSL");
      }

      /* Run analysis */
      worker.runAnalyzer();

      /* Run gates */
      worker.runGates();

      /* Run queries and continue even if it fails */
      try {
        worker.runQueries();
      } catch (Exception e) {
        console.logWarn("Recording failure to execute Anchore queries and moving on with plugin operation", e);
      }

      /* Setup reports */
      worker.setupBuildReports();
      
      /* Determine build result based on Anchore gates and status thresholds */
      run.setResult(worker.evalGates());
      
    } catch (Exception e) {
      if ((null != config && config.getBailOnPluginFail()) || bailOnPluginFail) {
        console.logError("Failing Anchore Container Image Scanner Plugin step due to errors in plugin execution", e);
        if (e instanceof AbortException) {
          throw e;
        } else {
          throw new AbortException("Failing Anchore Container Image Scanner Plugin step due to errors in plugin execution");
        }
      } else {
        console.logWarn("Marking Anchore Container Image Scanner step as successful despite errors in plugin execution");
      }
    } finally {
      // Wrap cleanup in try catch block to ensure this finally block does not throw an exception
      if (null != worker) {
        try {
          worker.cleanup();
        } catch (Exception e) {
          console.logDebug("Failed to cleanup after the plugin, ignoring the errors", e);
        }
      }
      console.logInfo("Completed Anchore Container Image Scanner step");
      LOG.warning("Completed Anchore Container Image Scanner step, project: " + run.getParent().getDisplayName() + ", job: " + run
          .getNumber());
    }
  }

  @Override
  public DescriptorImpl getDescriptor() {
    return (DescriptorImpl) super.getDescriptor();
  }

  @Symbol("anchore") // For Jenkins pipeline workflow. This lets pipeline refer to step using the defined identifier
  @Extension // This indicates to Jenkins that this is an implementation of an extension point.
  public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

    // Default job level config that may be used both by config.jelly and an instance of AnchoreBuilder
    public static final String DEFAULT_NAME = "anchore_images";
    public static final String DEFAULT_POLICY_NAME = "anchore_policy";
    public static final String DEFAULT_GLOBAL_WHITELIST = "anchore_global_whitelist";
    public static final String DEFAULT_ANCHORE_IO_USER = "";
    public static final String DEFAULT_ANCHORE_IO_PASSWORD = "";
    public static final String DEFAULT_USER_SCRIPTS = "anchore_user_scripts";
    public static final String DEFAULT_ENGINE_RETRIES = "300";
    public static final boolean DEFAULT_BAIL_ON_FAIL = false;
    public static final boolean DEFAULT_BAIL_ON_WARN = false;
    public static final boolean DEFAULT_BAIL_ON_PLUGIN_FAIL = true;
    public static final boolean DEFAULT_DO_CLEANUP = false;
    public static final boolean DEFAULT_USE_CACHED_BUNDLE = true;
    public static final String DEFAULT_POLICY_EVAL_METHOD = "plainfile";
    public static final String DEFAULT_BUNDLE_FILE_OVERRIDE = "anchore_policy_bundle.json";
    public static final String DEFAULT_PLUGIN_MODE = "anchoreengine";
    public static final List<AnchoreQuery> DEFAULT_INPUT_QUERIES = ImmutableList
        .of(new AnchoreQuery("cve-scan all"), new AnchoreQuery("list-packages all"), new AnchoreQuery("list-files all"),
            new AnchoreQuery("show-pkg-diffs base"));
    public static final String DEFAULT_POLICY_BUNDLE_ID = "";
    public static final double DEFAULT_STOP_ACTION_HEALTH_FACTOR = 25;
    public static final double DEFAULT_WARN_ACTION_HEALTH_FACTOR = 5;
    public static final Integer DEFAULT_UNSTABLE_STOP_THRESHOLD = null;
    public static final Integer DEFAULT_UNSTABLE_WARN_THRESHOLD = 1;
    public static final Integer DEFAULT_FAILED_STOP_THRESHOLD = 1;
    public static final Integer DEFAULT_FAILED_WARN_THRESHOLD = null;
    public static final String EMPTY_STRING = "";

    // Global configuration
    private boolean debug;
    private String enginemode;
    private String engineurl;
    private String engineuser;
    private Secret enginepass;
    private boolean engineverify;
    private String containerImageId;
    private String containerId;
    private String localVol;
    private String modulesVol;
    private boolean useSudo;

    // Upgrade case, you can never really remove these variables once they are introduced
    @Deprecated
    private boolean enabled;

    public void setDebug(boolean debug) {
      this.debug = debug;
    }

    @Deprecated
    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public void setEnginemode(String enginemode) {
      this.enginemode = enginemode;
    }

    public void setEngineurl(String engineurl) {
      this.engineurl = engineurl;
    }

    public void setEngineuser(String engineuser) {
      this.engineuser = engineuser;
    }

    public void setEnginepass(Secret enginepass) {
      this.enginepass = enginepass;
    }

    public void setEngineverify(boolean engineverify) {
      this.engineverify = engineverify;
    }

    public void setContainerImageId(String containerImageId) {
      this.containerImageId = containerImageId;
    }

    public void setContainerId(String containerId) {
      this.containerId = containerId;
    }

    public void setLocalVol(String localVol) {
      this.localVol = localVol;
    }

    public void setModulesVol(String modulesVol) {
      this.modulesVol = modulesVol;
    }

    public void setUseSudo(boolean useSudo) {
      this.useSudo = useSudo;
    }

    public boolean getDebug() {
      return debug;
    }

    @Deprecated
    public boolean getEnabled() {
      return enabled;
    }

    public String getEnginemode() {
      if (Strings.isNullOrEmpty(enginemode)) {
        enginemode = DEFAULT_PLUGIN_MODE;
      }
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

    public Secret getEnginepass() {
      return enginepass;
    }

    public boolean getEngineverify() {
      return engineverify;
    }

    public boolean getUseSudo() {
      return useSudo;
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

    public DescriptorImpl() {
      load();
    }

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> aClass) {
      return true;
    }

    @Override
    public String getDisplayName() {
      return "Anchore Container Image Scanner";
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
      req.bindJSON(this, formData); // Use stapler request to bind
      save();
      return true;
    }

    /**
     * Performs on-the-fly validation of the form field 'name' (Image list file)
     *
     * @param value This parameter receives the value that the user has typed in the 'Image list file' box
     * @return Indicates the outcome of the validation. This is sent to the browser. <p> Note that returning {@link
     * FormValidation#error(String)} does not prevent the form from being saved. It just means that a message will be displayed to the
     * user
     */
    @SuppressWarnings("unused")
    public FormValidation doCheckName(@QueryParameter String value) {
      if (!Strings.isNullOrEmpty(value)) {
        return FormValidation.ok();
      } else {
        return FormValidation.error("Please enter a valid file name");
      }
    }

    @SuppressWarnings("unused")
    public FormValidation doCheckContainerImageId(@QueryParameter String value) {
      if (!Strings.isNullOrEmpty(value)) {
        return FormValidation.ok();
      } else {
        return FormValidation.error("Please provide a valid Anchore Container Image ID");
      }
    }

    @SuppressWarnings("unused")
    public FormValidation doCheckContainerId(@QueryParameter String value) {
      if (!Strings.isNullOrEmpty(value)) {
        return FormValidation.ok();
      } else {
        return FormValidation.error("Please provide a valid Anchore Container ID");
      }
    }

    @SuppressWarnings("unused")
    public ListBoxModel doFillEngineCredentialsIdItems(@QueryParameter String credentialsId) {
      StandardListBoxModel result = new StandardListBoxModel();

      if (!Jenkins.getActiveInstance().hasPermission(Jenkins.ADMINISTER)) {
        return result.includeCurrentValue(credentialsId);
      }

      return result.includeEmptyValue()
          .includeMatchingAs(ACL.SYSTEM, Jenkins.getActiveInstance(), StandardUsernamePasswordCredentials.class,
              Collections.<DomainRequirement>emptyList(), CredentialsMatchers.always());
    }
  }
}

