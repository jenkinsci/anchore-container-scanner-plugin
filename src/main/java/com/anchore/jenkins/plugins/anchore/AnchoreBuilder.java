package com.anchore.jenkins.plugins.anchore;


import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import hudson.AbortException;
import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * <p>The Anchore Jenkins Plugin enables jenkins users the ability to add a build step to a jenkins job that executes anchore analysis,
 * gate policy evaluation, image scanning, and customizable anchore container image queries.</p>
 *
 * <p>Requirements:</p>
 *
 * <ol>
 * <li>Jenkins installed and configured either as a single system, or with multiple configured jenkins worker nodes</li>
 *
 * <li>Each host on which jenkins jobs will run must have docker installed and the jenkins user (or whichever user you have configured
 * jenkins to run jobs as) must be allowed to interact with docker (either directly or via sudo)</li>
 *
 * <li>Each host on which jenkins jobs will run must have the latest anchore container image installed in the local docker host. To
 * install, run 'docker pull anchore/jenkins:latest' on each jenkins host to make the image available to the plugin. The plugin will
 * start an instance of the anchore/jenkins:latest docker container named 'jenkins_anchore' by default, on each host that runs a
 * jenkins job that includes an Anchore Container Image Scanner build step.</li>
 * </ol>
 */

public class AnchoreBuilder extends Builder {

  //  Log handler for logging above INFO level events to jenkins log
  private static final Logger LOG = Logger.getLogger(AnchoreBuilder.class.getName());

  // Job/build configuration
  private String name;
  private String policyName;
  private String userScripts;
  private boolean bailOnFail;
  private boolean bailOnWarn;
  private boolean bailOnPluginFail;
  private boolean doCleanup;
  private List<AnchoreQuery> inputQueries;

  // Keeping these around for upgrade
  private boolean doQuery;
  private String query1;
  private String query2;
  private String query3;
  private String query4;

  // Getters are used by config.jelly
  public String getName() {
    return (name);
  }

  public String getPolicyName() {
    return (policyName);
  }

  public String getUserScripts() {
    return (userScripts);
  }

  public boolean getBailOnFail() {
    return (bailOnFail);
  }

  public boolean getBailOnWarn() {
    return (bailOnWarn);
  }

  public boolean getBailOnPluginFail() {
    return (bailOnPluginFail);
  }

  public boolean getDoCleanup() {
    return (doCleanup);
  }

  public List<AnchoreQuery> getInputQueries() {
    return inputQueries;
  }

  public boolean isDoQuery() {
    return doQuery;
  }

  public String getQuery1() {
    return query1;
  }

  public String getQuery2() {
    return query2;
  }

  public String getQuery3() {
    return query3;
  }

  public String getQuery4() {
    return query4;
  }

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
  @DataBoundConstructor
  public AnchoreBuilder(String name, String policyName, String userScripts, boolean bailOnFail, boolean bailOnWarn,
      boolean bailOnPluginFail, boolean doCleanup, AnchoreQueriesBlock queriesBlock) {
    this.name = name;
    this.policyName = policyName;
    this.userScripts = userScripts;
    this.bailOnFail = bailOnFail;
    this.bailOnWarn = bailOnWarn;
    this.bailOnPluginFail = bailOnPluginFail;
    this.doCleanup = doCleanup;
    if (null != queriesBlock) {
      this.inputQueries = queriesBlock.inputQueries;
    }
  }

  public static class AnchoreQueriesBlock {

    private List<AnchoreQuery> inputQueries;

    @DataBoundConstructor
    public AnchoreQueriesBlock(List<AnchoreQuery> inputQueries) {
      this.inputQueries = inputQueries != null ? new ArrayList<>(inputQueries) : Collections.<AnchoreQuery>emptyList();
    }
  }

  @Override
  public boolean perform(AbstractBuild build, Launcher inLauncher, BuildListener listener) throws AbortException {

    LOG.warning(
        "Starting Anchore Container Image Scanner build step, project: " + build.getParent().getDisplayName() + ", job: " + build
            .getNumber());

    BuildWorker worker = null;
    DescriptorImpl globalConfig = getDescriptor();
    ConsoleLog console = new ConsoleLog("AnchorePlugin", listener.getLogger(), globalConfig.getDebug());

    try {
      // Instantiate a new build worker
      worker = new BuildWorker(build, inLauncher, listener,
          new BuildConfig(name, policyName, userScripts, bailOnFail, bailOnWarn, bailOnPluginFail, doCleanup, inputQueries,
              globalConfig.getDebug(), globalConfig.getEnabled(), globalConfig.getContainerImageId(), globalConfig.getContainerId(),
              globalConfig.getLocalVol(), globalConfig.getModulesVol(), globalConfig.getUseSudo()));


       /* Run analysis */
      worker.runAnalyzer();


      /* Run gates */
      GATE_ACTION finalAction = worker.runGates();


      /* Run queries and continue even if it fails */
      try {
        worker.runQueries();
      } catch (Exception e) {
        console.logWarn("Recording failure to execute Anchore queries and moving on with plugin operation", e);
      }


      /* Setup reports */
      worker.setupBuildReports();


      /* Evaluate result of build step based on gate action */
      if (null != finalAction) {
        if ((bailOnFail && GATE_ACTION.STOP.equals(finalAction)) || (bailOnWarn && GATE_ACTION.WARN.equals(finalAction))) {
          console.logWarn("Failing Anchore Container Image Scanner Plugin build step due to final gate result " + finalAction);
          return false;
        } else {
          console.logInfo("Marking Anchore Container Image Scanner build step as successful, final gate result " + finalAction);
          return true;
        }
      } else {
        console.logInfo("Marking Anchore Container Image Scanner build step as successful, no final gate result");
        return true;
      }
    } catch (Exception e) {
      console.logError("Failed to execute Anchore Image Scanner Plugin build step", e);
      if (bailOnPluginFail) {
        console.logWarn("Failing Anchore Container Image Scanner Plugin build step due to errors in plugin execution");
        return false;
      } else {
        console.logWarn("Marking Anchore Container Image Scanner build step as successful despite errors in plugin execution");
        return true;
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
      console.logInfo("Completed Anchore Container Image Scanner build step");
      LOG.warning(
          "Completed Anchore Container Image Scanner build step, project: " + build.getParent().getDisplayName() + ", job: " + build
              .getNumber());
    }
  }

  @Override
  public DescriptorImpl getDescriptor() {
    return (DescriptorImpl) super.getDescriptor();
  }

  @Extension // This indicates to Jenkins that this is an implementation of an extension point.
  public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

    // Global configuration

    private boolean debug;
    private boolean enabled;
    private String containerImageId;
    private String containerId;
    private String localVol;
    private String modulesVol;
    private boolean useSudo;

    private static final List<AnchoreQuery> DEFAULT_QUERIES = ImmutableList
        .of(new AnchoreQuery("list-packages all"), new AnchoreQuery("list-files all"), new AnchoreQuery("cve-scan all"),
            new AnchoreQuery("show-pkg-diffs base"));

    public boolean getDebug() {
      return debug;
    }

    public boolean getEnabled() {
      return enabled;
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

    public List<AnchoreQuery> getDefaultQueries() {
      return DEFAULT_QUERIES;
    }

    public List<AnchoreQuery> getQueries(String query1, String query2, String query3, String query4) {
      List<AnchoreQuery> toBeReturned = new ArrayList<>();
      if (!Strings.isNullOrEmpty(query1)) {
        toBeReturned.add(new AnchoreQuery(query1));
      }
      if (!Strings.isNullOrEmpty(query2)) {
        toBeReturned.add(new AnchoreQuery(query2));
      }
      if (!Strings.isNullOrEmpty(query3)) {
        toBeReturned.add(new AnchoreQuery(query3));
      }
      if (!Strings.isNullOrEmpty(query4)) {
        toBeReturned.add(new AnchoreQuery(query4));
      }
      if (toBeReturned.isEmpty()) {
        return DEFAULT_QUERIES;
      } else {
        return toBeReturned;
      }
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
      debug = formData.getBoolean("debug");
      enabled = formData.getBoolean("enabled");
      useSudo = formData.getBoolean("useSudo");
      containerImageId = formData.getString("containerImageId");
      containerId = formData.getString("containerId");
      localVol = formData.getString("localVol");
      modulesVol = formData.getString("modulesVol");

      save();
      return super.configure(req, formData);
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

