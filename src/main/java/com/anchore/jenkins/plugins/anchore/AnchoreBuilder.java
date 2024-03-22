package com.anchore.jenkins.plugins.anchore;


import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.common.base.Strings;
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
  private String engineRetries = DescriptorImpl.DEFAULT_ENGINE_RETRIES;
  private boolean bailOnFail = DescriptorImpl.DEFAULT_BAIL_ON_FAIL;
  private boolean bailOnPluginFail = DescriptorImpl.DEFAULT_BAIL_ON_PLUGIN_FAIL;
  private String policyBundleId = DescriptorImpl.DEFAULT_POLICY_BUNDLE_ID;
  private List<Annotation> annotations;
  private boolean autoSubscribeTagUpdates = DescriptorImpl.DEFAULT_AUTOSUBSCRIBE_TAG_UPDATES;
  private boolean forceAnalyze = DescriptorImpl.DEFAULT_FORCE_ANALYZE;
  private boolean excludeFromBaseImage = DescriptorImpl.DEFAULT_EXCLUDE_FROM_BASE_IMAGE;

  // Override global config. Supported for anchore-enterprise mode config only
  private String engineurl = DescriptorImpl.EMPTY_STRING;
  private String engineCredentialsId = DescriptorImpl.EMPTY_STRING;
  private boolean engineverify = false;
  // More flags to indicate boolean override, ugh!
  private boolean isEngineverifyOverrride = false;

  // Getters are used by config.jelly
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
  public void setEngineRetries(String engineRetries) {
    this.engineRetries = engineRetries;
  }

  @DataBoundSetter
  public void setBailOnFail(boolean bailOnFail) {
    this.bailOnFail = bailOnFail;
  }

  @DataBoundSetter
  public void setBailOnPluginFail(boolean bailOnPluginFail) {
    this.bailOnPluginFail = bailOnPluginFail;
  }

  @DataBoundSetter
  public void setPolicyBundleId(String policyBundleId) {
    this.policyBundleId = policyBundleId;
  }

  @DataBoundSetter
  public void setAnnotations(List<Annotation> annotations) {
    this.annotations = annotations;
  }

  @DataBoundSetter
  public void setAutoSubscribeTagUpdates(boolean autoSubscribeTagUpdates) {
    this.autoSubscribeTagUpdates = autoSubscribeTagUpdates;
  }

  @DataBoundSetter
  public void setForceAnalyze(boolean forceAnalyze) {
    this.forceAnalyze = forceAnalyze;
  }

  @DataBoundSetter
  public void setExcludeFromBaseImage(boolean excludeFromBaseImage) {
    this.excludeFromBaseImage = excludeFromBaseImage;
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

    boolean failedByGate = false;
    BuildConfig config = null;
    BuildWorker worker = null;
    DescriptorImpl globalConfig = getDescriptor();
    ConsoleLog console = new ConsoleLog("AnchorePlugin", listener.getLogger(), globalConfig.getDebug());

    GATE_ACTION finalAction;

    try {

      /* Fetch Jenkins creds first, can't push this lower down the chain since it requires Jenkins instance object */
      String engineuser = null;
      String enginepass = null;
      if (!Strings.isNullOrEmpty(engineCredentialsId)) {
        console.logDebug("Found build override for anchore-enterprise credentials. Processing Jenkins credential ID ");
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
      config = new BuildConfig(name, engineRetries, bailOnFail,
          bailOnPluginFail, policyBundleId, annotations, autoSubscribeTagUpdates, forceAnalyze, excludeFromBaseImage, globalConfig.getDebug(),
          // messy build time overrides, ugh!
          !Strings.isNullOrEmpty(engineurl) ? engineurl : globalConfig.getEngineurl(),
          !Strings.isNullOrEmpty(engineuser) ? engineuser : globalConfig.getEngineuser(),
          !Strings.isNullOrEmpty(enginepass) ? enginepass : globalConfig.getEnginepass().getPlainText(),
          isEngineverifyOverrride ? engineverify : globalConfig.getEngineverify());
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
      finalAction = worker.runGates();

      /* Run queries and continue even if it fails */
      try {
        worker.runQueries();
      } catch (Exception e) {
        console.logWarn("Recording failure to execute Anchore queries and moving on with plugin operation", e);
      }

      /* Setup reports */
      worker.setupBuildReports();

      /* Evaluate result of step based on gate action */
      if (null != finalAction) {
        if (config.getBailOnFail() && (GATE_ACTION.STOP.equals(finalAction) || GATE_ACTION.FAIL.equals(finalAction))) {
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
      } else if ((null != config && config.getBailOnPluginFail()) || bailOnPluginFail) {
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
    public static final String DEFAULT_ENGINE_RETRIES = "300";
    public static final boolean DEFAULT_BAIL_ON_FAIL = true;
    public static final boolean DEFAULT_BAIL_ON_PLUGIN_FAIL = true;
    public static final String DEFAULT_PLUGIN_MODE = "anchoreengine";
    public static final String DEFAULT_POLICY_BUNDLE_ID = "";
    public static final String EMPTY_STRING = "";
    public static final boolean DEFAULT_AUTOSUBSCRIBE_TAG_UPDATES = true;
    public static final boolean DEFAULT_FORCE_ANALYZE = false;
    public static final boolean DEFAULT_EXCLUDE_FROM_BASE_IMAGE = false;

    // Global configuration
    private boolean debug;
    private String engineurl;
    private String engineuser;
    private Secret enginepass;
    private boolean engineverify;

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

    public boolean getDebug() {
      return debug;
    }

    @Deprecated
    public boolean getEnabled() {
      return enabled;
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

