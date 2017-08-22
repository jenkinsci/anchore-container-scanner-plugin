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
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import net.sf.json.JSONArray;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.codec.binary.Base64;

/**
 * <p>Anchore Plugin enables Jenkins users to scan container images, generate analysis, evaluate gate policy, and execute customizable
 * queries. The plugin can be used in a freestyle project as a build step or invoked from a pipeline script</p>
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
 * jenkins job that includes an Anchore Container Image Scanner build step.</li> </ol>
 */
public class AnchoreBuilder extends Builder implements SimpleBuildStep {

  //  Log handler for logging above INFO level events to jenkins log
  private static final Logger LOG = Logger.getLogger(AnchoreBuilder.class.getName());

  // Job/build configuration
  private String name;
  private String policyName;
  private String globalWhiteList;
  private String anchoreioUser;
  private String anchoreioPass;
  private String userScripts;
  private String engineRetries;
  private boolean bailOnFail = true;
  private boolean bailOnWarn = false;
  private boolean bailOnPluginFail = true;
  private boolean doCleanup = false;
  private boolean useCachedBundle = true;
  private String policyEvalMethod;
  private String bundleFileOverride;
  private List<AnchoreQuery> inputQueries;

  // Keeping these around for upgrade
  @Deprecated
  private boolean doQuery;
  @Deprecated
  private String query1;
  @Deprecated
  private String query2;
  @Deprecated
  private String query3;
  @Deprecated
  private String query4;

  // Getters are used by config.jelly
  public String getName() {
    return (name);
  }

  public String getPolicyName() {
    return (policyName);
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
    return (userScripts);
  }

  public String getEngineRetries() {
    return (engineRetries);
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

  public boolean getUseCachedBundle() {
    return (useCachedBundle);
  }

  public String getPolicyEvalMethod() {
    return (policyEvalMethod);
  }

  public String getBundleFileOverride() {
    return (bundleFileOverride);
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
  public void setQueriesBlock(AnchoreQueriesBlock queriesBlock) {
    if (null != queriesBlock) {
      this.inputQueries = queriesBlock.getInputQueries();
    }
  }

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor" or "DataBoundSetter"
  @DataBoundConstructor
  public AnchoreBuilder(String name) {
    this.name = name;
  }

  @Override
  public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener)
      throws InterruptedException, IOException {

    LOG.warning("Starting Anchore Container Image Scanner build step, project: " + run.getParent().getDisplayName() + ", job: " + run
        .getNumber());

    boolean failedByGate = false;
    BuildWorker worker = null;
    DescriptorImpl globalConfig = getDescriptor();
    ConsoleLog console = new ConsoleLog("AnchorePlugin", listener.getLogger(), globalConfig.getDebug());

    GATE_ACTION finalAction;

    try {

	if (false) {

	} else {
	    // Instantiate a new build worker
	    worker = new BuildWorker(run, workspace, launcher, listener, new BuildConfig(name, policyName, globalWhiteList, anchoreioUser, anchoreioPass, userScripts, engineRetries, bailOnFail, bailOnWarn, bailOnPluginFail, doCleanup, useCachedBundle, policyEvalMethod, bundleFileOverride, inputQueries, globalConfig.getDebug(), globalConfig.getEnabled(), globalConfig.getEnginemode(), globalConfig.getEngineurl(), globalConfig.getEngineuser(), globalConfig.getEnginepass(), globalConfig.getContainerImageId(), globalConfig.getContainerId(), globalConfig.getLocalVol(), globalConfig.getModulesVol(), globalConfig.getUseSudo()));
	    
	    
	    /* Run analysis */
	    worker.runAnalyzer();
	    
	    /* Run gates */
	    finalAction = worker.runGates();
	    
	    if (globalConfig.getEnginemode().equals("anchorelocal")) {
		/* Run queries and continue even if it fails */
		try {
		    worker.runQueries();
		} catch (Exception e) {
		console.logWarn("Recording failure to execute Anchore queries and moving on with plugin operation", e);
		}
		
	    }
	    /* Setup reports */
	    worker.setupBuildReports();

	}	    
	/* Evaluate result of build step based on gate action */
	if (null != finalAction) {
	    if ((bailOnFail && GATE_ACTION.STOP.equals(finalAction)) || (bailOnWarn && GATE_ACTION.WARN.equals(finalAction))) {
		console.logWarn("Failing Anchore Container Image Scanner Plugin build step due to final gate result " + finalAction);
		failedByGate = true;
		throw new AbortException(
					 "Failing Anchore Container Image Scanner Plugin build step due to final gate result " + finalAction);
	    } else {
		console.logInfo("Marking Anchore Container Image Scanner build step as successful, final gate result " + finalAction);
	    }
	} else {
	    console.logInfo("Marking Anchore Container Image Scanner build step as successful, no final gate result");
	}
	    
    } catch (Exception e) {
	if (failedByGate) {
	    throw e;
	} else if (bailOnPluginFail) {
	    console.logError("Failing Anchore Container Image Scanner Plugin build step due to errors in plugin execution", e);
	    if (e instanceof AbortException) {
		throw e;
	    } else {
		throw new AbortException("Failing Anchore Container Image Scanner Plugin build step due to errors in plugin execution");
	    }
	} else {
	    console.logWarn("Marking Anchore Container Image Scanner build step as successful despite errors in plugin execution");
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
		    "Completed Anchore Container Image Scanner build step, project: " + run.getParent().getDisplayName() + ", job: " + run
		    .getNumber());
    }
  }
    
  @Override
  public DescriptorImpl getDescriptor() {
    return (DescriptorImpl) super.getDescriptor();
  }

  @Symbol("anchore") // For Jenkins pipeline workflow. This lets pipeline refer to build step using the defined identifier
  @Extension // This indicates to Jenkins that this is an implementation of an extension point.
  public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

    // Global configuration

    private boolean debug;
    private boolean enabled;
    private String enginemode;
    private String engineurl;
    private String engineuser;
    private String enginepass;
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

    public String getEnginemode() {
      return enginemode;
    }

    public boolean isMode(String inmode) {
	if (enginemode == null && inmode.equals("anchorelocal")) {
	    return(true);
	}
	if (enginemode.equals(inmode)) {
	    return(true);
	}

	return(false);
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
      enginemode = formData.getString("enginemode");
      engineurl = formData.getString("engineurl");
      engineuser = formData.getString("engineuser");
      enginepass = formData.getString("enginepass");
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

