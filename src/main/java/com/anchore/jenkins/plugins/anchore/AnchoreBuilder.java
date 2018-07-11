package com.anchore.jenkins.plugins.anchore;


import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
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

    boolean failedByGate = false;
    BuildWorker worker = null;
    DescriptorImpl globalConfig = getDescriptor();
    ConsoleLog console = new ConsoleLog("AnchorePlugin", listener.getLogger(), globalConfig.getDebug());

    GATE_ACTION finalAction;

    try {

      // Instantiate a new build worker
      worker = new BuildWorker(run, workspace, launcher, listener,
          new BuildConfig(name, policyName, globalWhiteList, anchoreioUser, anchoreioPass, userScripts, engineRetries, bailOnFail,
              bailOnWarn, bailOnPluginFail, doCleanup, useCachedBundle, policyEvalMethod, bundleFileOverride, inputQueries,
              policyBundleId, globalConfig.getDebug(), globalConfig.getEnginemode(), globalConfig.getEngineurl(),
              globalConfig.getEngineuser(), globalConfig.getEnginepass(), globalConfig.getEngineverify(),
              globalConfig.getContainerImageId(), globalConfig.getContainerId(), globalConfig.getLocalVol(),
              globalConfig.getModulesVol(), globalConfig.getUseSudo()));

      /* Run analysis */
      worker.runAnalyzer();

      /* Run gates */
      finalAction = worker.runGates();

      /* Run queries and continue even if it fails */
      if (globalConfig.getEnginemode().equals("anchorelocal")) {
        try {
          worker.runQueries();
        } catch (Exception e) {
          console.logWarn("Recording failure to execute Anchore queries and moving on with plugin operation", e);
        }
      }

      /* Setup reports */
      worker.setupBuildReports();

      /* Evaluate result of step based on gate action */
      if (null != finalAction) {
        if ((bailOnFail && (GATE_ACTION.STOP.equals(finalAction) || GATE_ACTION.FAIL.equals(finalAction))) || (bailOnWarn
            && GATE_ACTION.WARN.equals(finalAction))) {
          console.logWarn("Failing Anchore Container Image Scanner Plugin step due to final result " + finalAction);
          failedByGate = true;
          throw new AbortException("Failing Anchore Container Image Scanner Plugin step due to final result " + finalAction);
        } else {
          console.logInfo("Marking Anchore Container Image Scanner step as successful, final result " + finalAction);
        }
      } else {
        console.logInfo("Marking Anchore Container Image Scanner step as successful, no final result");
      }

    } catch (Exception e) {
      if (failedByGate) {
        throw e;
      } else if (bailOnPluginFail) {
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
    public static final boolean DEFAULT_BAIL_ON_FAIL = true;
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

    public void setEnginepass(String enginepass) {
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

    public String getEnginepass() {
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
    public FormValidation doCheckName(@QueryParameter String value) {
      if (!Strings.isNullOrEmpty(value)) {
        return FormValidation.ok();
      } else {
        return FormValidation.error("Please enter a valid file name");
      }
    }

    public FormValidation doCheckContainerImageId(@QueryParameter String value) {
      if (!Strings.isNullOrEmpty(value)) {
        return FormValidation.ok();
      } else {
        return FormValidation.error("Please provide a valid Anchore Container Image ID");
      }
    }

    public FormValidation doCheckContainerId(@QueryParameter String value) {
      if (!Strings.isNullOrEmpty(value)) {
        return FormValidation.ok();
      } else {
        return FormValidation.error("Please provide a valid Anchore Container ID");
      }
    }
  }
}

