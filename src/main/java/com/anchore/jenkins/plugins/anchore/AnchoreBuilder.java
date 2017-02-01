package com.anchore.jenkins.plugins.anchore;


import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.PluginWrapper;
import hudson.Util;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Node;
import hudson.tasks.ArtifactArchiver;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import jenkins.model.Jenkins;
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
  // This is probably the slowest way of formatting strings, should do for now but please figure out a better way
  private static final String LOG_FORMAT = "%1$tY-%1$tm-%1$tdT%1$tH:%1$tM:%1$tS.%1$tL %2$-6s AnchorePlugin %3$s";
  private static final Splitter IMAGE_LIST_SPLITTER = Splitter.on(Pattern.compile("\\s+")).trimResults().omitEmptyStrings();
  private static final String ANCHORE_BINARY = "anchore";
  private static final String ANCHORE_CSS = "/plugin/anchore-container-scanner/css/anchore.css";

  private enum GATE_ACTION {STOP, WARN, GO}

  // Build configuration
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

  // Initialized at the very beginning of perform()
  private PrintStream buildLog; // Log handler for logging to build console
  private boolean enableDebug; // Class member to avoid passing DescriptorImpl for debug logging
  private String buildId;

  // Initialized by Jenkins workspace prep // TODO check if this creates problems during upgrade
  private String jenkinsOutputDirName;
  // Populated as you go along
  private GATE_ACTION finalAction;

  // Initialized by Anchore workspace prep
  private String anchoreWorkspaceDirName;
  private List<String> anchoreInputImages;
  private String anchoreImageFile;
  private String anchorePolicyFileName;
  private String anchoreScriptsDirName;

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
    this.doCleanup = doCleanup;
    this.bailOnPluginFail = bailOnPluginFail;
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

    // Declaring them here as they are used by finally block
    DescriptorImpl globalConfig = null;
    Launcher jenkinsLauncher = null;

    try {
      LOG.warning(
          "Starting Anchore Container Image Scanner plugin, project: " + build.getParent().getDisplayName() + ", build: " + build
              .getNumber());


      /* Some basic initialization here because Jenkins does not like complex class members due to serialization issues.
      May be all of this could be refactored into a different class at a later time */

      //      // Initialize console logger and global configuration before doing anything. Behaves like a constructor in lieu of a
      // real one
      //      initializeBasics(build, listener);

      // Initialize build logger to log output to console, use local logging methods only after this initializer completes
      if (null == listener || null == (buildLog = listener.getLogger())) {
        LOG.warning("Anchore Container Image Scanner plugin cannot access build listener");
        throw new AbortException("Anchore Container Image Scanner plugin cannot access build listener. Aborting plugin");
      }
      logInfo("Starting Anchore Container Image Scanner plugin, project: " + build.getParent().getDisplayName() + ", build: " + build
          .getNumber());

      // Fetch and initialize global configuration
      if (null == (globalConfig = getDescriptor())) {
        logError("Global configuration for the plugin is invalid");
        throw new AbortException(
            "Global configuration for the plugin is invalid. Please configure the plugin under Manage Jenkins->Configure "
                + "System->Anchore Configuration and retry");
      }

      // Initialize debug logging
      enableDebug = globalConfig.getDebug();

      // TODO is this necessary? Can't we use the launcher that was passed in
      Node jenkinsNode = build.getBuiltOn();
      if (null == jenkinsNode || null == (jenkinsLauncher = jenkinsNode.createLauncher(listener))) {
        LOG.warning("Anchore Container Image Scanner plugin is unable to initialize Jenkins process executor");
        logError("Unable to initialize Jenkins process executor");
        throw new AbortException("Unable to initialize Jenkins process executor");
      }

      if (Strings.isNullOrEmpty(buildId = build.getParent().getDisplayName() + "_" + build.getNumber())) {
        logWarn("Unable to generate a unique identifier for this build due to invalid configuration");
        throw new AbortException("Unable to generate a unique identifier for this build due to invalid configuration");
      }


      /* Print build and global configuration */
      printConfig(globalConfig);


      /* Check config */
      checkConfig(build, globalConfig);


      /* Initialize Jenkins workspace */
      initializeJenkinsWorkspace(build);
      // Cannot be a class member due to serialization issues
      Map<String, FilePath> jenkinsGeneratedOutput = new HashMap<>(); // Output files generated by processes
      Map<String, String> successfulQueries = new HashMap<>(); // TODO refactor this


      /* Initialize Anchore workspace */
      initializeAnchoreWorkspace(build, jenkinsLauncher, globalConfig);


      /* Run analysis */
      runAnalyzer(jenkinsLauncher, globalConfig);

      /* Run gates */
      runGates(build, jenkinsLauncher, globalConfig, jenkinsGeneratedOutput);


      /* Run queries and continue even if it fails */
      try {
        runQueries(build, jenkinsLauncher, globalConfig, jenkinsGeneratedOutput, successfulQueries);
      } catch (Exception e) {
        logWarn("Recording failure to execute Anchore queries and moving on with plugin operation", e);
      }


      /* Generate reports */
      generateReports(build, jenkinsGeneratedOutput, successfulQueries);


      /* Archive reports */
      archiveReports(build, jenkinsLauncher, listener);


      /* Evaluate end result, its is based on the gate action*/
      if (null != finalAction) {
        if ((bailOnFail && GATE_ACTION.STOP.equals(finalAction)) || (bailOnWarn && GATE_ACTION.WARN.equals(finalAction))) {
          logWarn("Failing Anchore Container Image Scanner Plugin build step due to final gate result " + finalAction);
          return false;
        } else {
          logInfo("Marking Anchore Container Image Scanner build step as successful, final gate result " + finalAction);
          return true;
        }
      } else {
        logInfo("Marking Anchore Container Image Scanner build step as successful, no final gate result");
        return true;
      }
    } catch (Exception e) {
      logError("Failed to execute Anchore Image Scanner Plugin build step", e);
      if (bailOnPluginFail) {
        logWarn("Failing Anchore Container Image Scanner Plugin build step due to errors in plugin execution");
        return false;
      } else {
        logWarn("Marking Anchore Container Image Scanner build step as successful despite errors in plugin execution");
        return true;
      }
    } finally {
      // Wrap cleanup in try catch block to ensure this finally block does not throw an exception
      if (null != jenkinsLauncher && null != globalConfig) {
        try {
          cleanup(build, jenkinsLauncher, globalConfig);
        } catch (Exception e) {
          logDebug("Failed to cleanup after the plugin, ignoring the errors", e);
        }
      }
      logInfo("Completed Anchore Container Image Scanner build step");
      LOG.warning("Completed Anchore Container Image Scanner build step");
    }
  }

  @Override
  public DescriptorImpl getDescriptor() {
    return (DescriptorImpl) super.getDescriptor();
  }

  private void printConfig(DescriptorImpl globalConfig) throws AbortException {

    logInfo("Jenkins version: " + Jenkins.VERSION);
    List<PluginWrapper> plugins;
    if (Jenkins.getActiveInstance() != null && Jenkins.getActiveInstance().getPluginManager() != null
        && (plugins = Jenkins.getActiveInstance().getPluginManager().getPlugins()) != null) {
      for (PluginWrapper plugin : plugins) {
        if (plugin.getShortName()
            .equals("anchore-container-scanner")) { // artifact ID of the plugin, TODO is there a better way to get this
          logInfo(plugin.getDisplayName() + " version: " + plugin.getVersion());
          break;
        }
      }
    }

    logInfo("[global] enabled: " + String.valueOf(globalConfig.getEnabled()));
    logInfo("[global] debug: " + String.valueOf(globalConfig.getDebug()));
    logInfo("[global] useSudo: " + String.valueOf(globalConfig.getUseSudo()));
    logInfo("[global] containerImageId: " + globalConfig.getContainerImageId());
    logInfo("[global] containerId: " + globalConfig.getContainerId());
    logInfo("[global] localVol: " + globalConfig.getLocalVol());
    logInfo("[global] modulesVol: " + globalConfig.getModulesVol());

    logInfo("[build] name: " + name);
    logInfo("[build] policyName: " + policyName);
    logInfo("[build] userScripts: " + userScripts);
    logInfo("[build] bailOnFail: " + bailOnFail);
    logInfo("[build] bailOnWarn: " + bailOnWarn);
    logInfo("[build] bailOnPluginFail: " + bailOnPluginFail);
    logInfo("[build] doCleanup: " + doCleanup);
    if (null != inputQueries && !inputQueries.isEmpty()) {
      for (AnchoreQuery anchoreQuery : inputQueries) {
        logInfo("[build] query: " + anchoreQuery.getQuery());
      }
    }
  }

  /**
   * Check if the minimum required config is available
   */
  private void checkConfig(AbstractBuild build, DescriptorImpl globalConfig) throws AbortException {
    if (!globalConfig.getEnabled()) {
      logError("Anchore image scanning is disabled");
      throw new AbortException(
          "Anchore image scanning is disabled. Please enable image scanning in Anchore Configuration under Manage Jenkins -> "
              + "Configure System and try again");
    }

    if (Strings.isNullOrEmpty(name)) {
      logError("Image list file not found");
      throw new AbortException(
          "Image list file not specified. Please specify a valid image list file name in the Anchore plugin build step "
              + "configuration and try again");
    }

    try {
      if (!new FilePath(build.getWorkspace(), name).exists()) {
        logError("Cannot open image list file " + name + " under " + build.getWorkspace());
        throw new AbortException("Cannot open image list file " + name
            + ". Please ensure that image list file is created prior to Anchore Container Image Scanner build step");
      }
    } catch (AbortException e) {
      throw e;
    } catch (Exception e) {
      logWarn("Unable to access image list file " + name + " under " + build.getWorkspace(), e);
      throw new AbortException("Unable to access image list file " + name
          + ". Please ensure that image list file is created prior to Anchore Container Image Scanner build step");
    }

    if (Strings.isNullOrEmpty(globalConfig.getContainerId())) {
      logError("Anchore Container ID not found");
      throw new AbortException(
          "Please configure \"Anchore Container ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry. If the"
              + " container is not running, the plugin will launch it");
    }

    // TODO docker and image checks necessary here? check with Dan

  }

  private void initializeJenkinsWorkspace(AbstractBuild build) throws AbortException {
    try {
      logDebug("Initializing Jenkins workspace");

      jenkinsOutputDirName = "AnchoreReport." + buildId;
      FilePath jenkinsReportDir = new FilePath(build.getWorkspace(), jenkinsOutputDirName);

      // Create output directories
      if (!jenkinsReportDir.exists()) {
        logDebug("Creating workspace directory " + jenkinsOutputDirName);
        jenkinsReportDir.mkdirs();
      }
    } catch (AbortException e) {
      // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      // caught unknown exception, log it and wrap it
      logWarn("Failed to initialize Jenkins workspace", e);
      throw new AbortException("Failed to initialize Jenkins workspace due to to an unexpected error");
    }
  }

  private void initializeAnchoreWorkspace(AbstractBuild build, Launcher jenkinsLauncher, DescriptorImpl globalConfig)
      throws AbortException {
    try {
      logDebug("Initializing Anchore workspace");

      // Setup the container first
      setupAnchoreContainer(jenkinsLauncher, globalConfig);

      // stage directory in anchore container
      anchoreWorkspaceDirName = "/root/anchore." + buildId;

      logDebug(
          "Creating build artifact directory " + anchoreWorkspaceDirName + " in Anchore container " + globalConfig.getContainerId());
      int rc = executeCommand(jenkinsLauncher, globalConfig,
          "docker exec " + globalConfig.getContainerId() + " mkdir -p " + anchoreWorkspaceDirName);
      if (rc != 0) {
        logError("Failed to create build artifact directory " + anchoreWorkspaceDirName + " in Anchore container " + globalConfig
            .getContainerId());
        throw new AbortException(
            "Failed to create build artifact directory " + anchoreWorkspaceDirName + " in Anchore container " + globalConfig
                .getContainerId());
      }

      // Sanitize the input image list
      // - Copy dockerfile for images to anchore container
      // - Create a staging file with adjusted paths
      logDebug("Staging image file in Jenkins workspace");
      anchoreInputImages = new ArrayList<>();
      FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
      FilePath jenkinsStagedImageFP = new FilePath(jenkinsOutputDirFP, "staged_images." + buildId);
      FilePath inputImageFP = new FilePath(build.getWorkspace(), name); // Already checked in checkConfig()

      try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsStagedImageFP.write(), StandardCharsets.UTF_8))) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputImageFP.read(), StandardCharsets.UTF_8))) {
          String line;
          int count = 0;
          while ((line = br.readLine()) != null) {
            // TODO check for a later libriary of guava that lets your slit strings into a list
            Iterable<String> iterable = IMAGE_LIST_SPLITTER.split(line);
            Iterator<String> partIterator;

            if (null != iterable && null != (partIterator = iterable.iterator()) && partIterator.hasNext()) {
              String imgId = partIterator.next();
              String lineToBeAdded = imgId;

              if (partIterator.hasNext()) {
                String jenkinsDFile = partIterator.next();
                String anchoreDFile = anchoreWorkspaceDirName + "/dfile." + (++count);

                // Copy file from Jenkins to Anchore container
                logDebug("Copying Dockerfile from Jenkins workspace: " + jenkinsDFile + ", to Anchore workspace: " + anchoreDFile);
                rc = executeCommand(jenkinsLauncher, globalConfig,
                    "docker cp " + jenkinsDFile + " " + globalConfig.getContainerId() + ":" + anchoreDFile);
                if (rc != 0) {
                  // TODO check with Dan if operation should continue for other images
                  logError(
                      "Failed to copy Dockerfile from Jenkins workspace: " + jenkinsDFile + ", to Anchore workspace: " + anchoreDFile);
                  throw new AbortException(
                      "Failed to copy Dockerfile from Jenkins workspace: " + jenkinsDFile + ", to Anchore workspace: " + anchoreDFile
                          + ". Please ensure that Dockerfile is present in the Jenkins workspace prior to running Anchore plugin");
                }
                lineToBeAdded += " " + anchoreDFile;
              } else {
                logWarn("No dockerfile specified for image " + imgId + ". Anchore analyzer will attempt to construct dockerfile");
              }

              logDebug("Staging sanitized entry: \"" + lineToBeAdded + "\"");

              lineToBeAdded += "\n";

              bw.write(lineToBeAdded);
              anchoreInputImages.add(imgId);
            } else {
              logWarn("Cannot parse: \"" + line
                  + "\". Format for each line in input image file is \"imageId /path/to/Dockerfile\", where the Dockerfile is "
                  + "optional");
            }
          }
        }
      }

      if (anchoreInputImages.isEmpty()) {
        // nothing to analyze here
        logError("List of input images to be analyzed is empty");
        throw new AbortException(
            "List of input images to be analyzed is empty. Please ensure that image file is populated with a list of images to be "
                + "analyzed. " + "Format for each line is \"imageId /path/to/Dockerfile\", where the Dockerfile is optional");
      }

      // finally, stage the rest of the files
      anchoreImageFile = anchoreWorkspaceDirName + "/images";
      logDebug("Copying staged image file from Jenkins workspace: " + jenkinsStagedImageFP.getRemote() + ", to Anchore workspace: "
          + anchoreImageFile);
      rc = executeCommand(jenkinsLauncher, globalConfig,
          "docker cp " + jenkinsStagedImageFP.getRemote() + " " + globalConfig.getContainerId() + ":" + anchoreImageFile);
      if (rc != 0) {
        logError(
            "Failed to copy staged image file from Jenkins workspace: " + jenkinsStagedImageFP.getRemote() + ", to Anchore workspace: "
                + anchoreImageFile);
        throw new AbortException(
            "Failed to copy staged image file from Jenkins workspace: " + jenkinsStagedImageFP.getRemote() + ", to Anchore workspace: "
                + anchoreImageFile);
      }

      try {
        FilePath jenkinsScriptsDir;
        if (!Strings.isNullOrEmpty(userScripts) && (jenkinsScriptsDir = new FilePath(build.getWorkspace(), userScripts)).exists()) {
          anchoreScriptsDirName = anchoreWorkspaceDirName + "/anchorescripts/";
          logDebug("Copying user scripts from Jenkins workspace: " + jenkinsScriptsDir.getRemote() + ", to Anchore workspace: "
              + anchoreScriptsDirName);
          rc = executeCommand(jenkinsLauncher, globalConfig,
              "docker cp " + jenkinsScriptsDir.getRemote() + " " + globalConfig.getContainerId() + ":" + anchoreScriptsDirName);
          if (rc != 0) {
            // TODO Check with Dan if we should abort or just move on with default
            logError(
                "Failed to copy user scripts from Jenkins workspace: " + jenkinsScriptsDir.getRemote() + ", to Anchore workspace: "
                    + anchoreScriptsDirName);
            throw new AbortException(
                "Failed to copy user scripts from Jenkins workspace: " + jenkinsScriptsDir.getRemote() + ", to Anchore workspace: "
                    + anchoreScriptsDirName);
          }
        } else {
          logDebug("No user scripts/modules found, using default Anchore modules");
        }
      } catch (IOException | InterruptedException e) {
        logWarn("Failed to resolve user modules, using default Anchore modules");
      }

      try {
        FilePath jenkinsPolicyFile;
        if (!Strings.isNullOrEmpty(policyName) && (jenkinsPolicyFile = new FilePath(build.getWorkspace(), policyName)).exists()) {
          logDebug("Copying policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
              + anchorePolicyFileName);
          anchorePolicyFileName = anchoreWorkspaceDirName + "/policy";
          rc = executeCommand(jenkinsLauncher, globalConfig,
              "docker cp " + jenkinsPolicyFile.getRemote() + " " + globalConfig.getContainerId() + ":" + anchorePolicyFileName);
          if (rc != 0) {
            // TODO check with Dan if we should abort tor just move on with default
            logWarn("Failed to copy policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
                + anchorePolicyFileName);
            throw new AbortException(
                "Failed to copy policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
                    + anchorePolicyFileName);
          }
        } else {
          logInfo("Policy file either not specified or does not exist, using default Anchore policy");
        }
      } catch (IOException | InterruptedException e) {
        logWarn("Failed to resolve user policy, using default Anchore policy");
      }
    } catch (AbortException e) {
      // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      // caught unknown exception, log it and wrap it
      logError("Failed to initialize Anchore workspace due to an unexpected error", e);
      throw new AbortException(
          "Failed to initialize Anchore workspace due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void runAnalyzer(Launcher jenkinsLauncher, DescriptorImpl globalConfig) throws AbortException {
    try {
      logInfo("Running Anchore Analyzer");

      int rc = executeAnchoreCommand(jenkinsLauncher, globalConfig, "analyze --imagefile " + anchoreImageFile);
      if (rc != 0) {
        logError("Anchore analyzer failed with return code " + rc + ", check output above for details");
        throw new AbortException("Anchore analyzer failed, check output above for details");
      }
      logDebug("Anchore analyzer completed successfully");
    } catch (AbortException e) {
      // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      // caught unknown exception, log it and wrap it
      logError("Failed to run Anchore analyzer due to an unexpected error", e);
      throw new AbortException(
          "Failed to run Anchore analyzer due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void runGates(AbstractBuild build, Launcher jenkinsLauncher, DescriptorImpl globalConfig,
      Map<String, FilePath> jenkinsGeneratedOutput) throws AbortException {
    try {
      logInfo("Running Anchore Gates");

      FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
      FilePath jenkinsGatesOutputFP = new FilePath(jenkinsOutputDirFP, "anchore_gates.html");
      String cmd = "--html gate --imagefile " + anchoreImageFile;

      if (!Strings.isNullOrEmpty(anchorePolicyFileName)) {
        cmd += " --policy " + anchorePolicyFileName;
      }

      try {
        int rc = executeAnchoreCommand(jenkinsLauncher, globalConfig, cmd, jenkinsGatesOutputFP.write());
        jenkinsGeneratedOutput.put("anchore_gates", jenkinsGatesOutputFP);
        switch (rc) {
          case 0:
            finalAction = GATE_ACTION.GO;
            break;
          case 2:
            finalAction = GATE_ACTION.WARN;
            break;
          default:
            finalAction = GATE_ACTION.STOP;
        }

        logDebug("Anchore gate execution completed successfully, final action: " + finalAction);
      } catch (IOException | InterruptedException e) {
        // TODO check with dan if we should error out or continue
        logWarn("Failed to write gates output to " + jenkinsGatesOutputFP.getRemote(), e);
        throw new AbortException("Failed to write gates output to " + jenkinsGatesOutputFP.getRemote());
      }
    } catch (AbortException e) {
      // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      // caught unknown exception, log it and wrap it
      logError("Failed to run Anchore gates due to an unexpected error", e);
      throw new AbortException(
          "Failed to run Anchore gates due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void runQueries(AbstractBuild build, Launcher jenkinsLauncher, DescriptorImpl globalConfig,
      Map<String, FilePath> jenkinsGeneratedOutput, Map<String, String> successfulQueries) throws AbortException {
    try {
      if (inputQueries != null && !inputQueries.isEmpty()) {
        int key = 0;
        for (AnchoreQuery query : inputQueries) {
          if (!Strings.isNullOrEmpty(query.getQuery())) {
            logInfo("Running Anchore Query: " + query.getQuery());
            String queryId = "query" + ++key;
            FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
            FilePath jenkinsQueryOutputFP = new FilePath(jenkinsOutputDirFP, queryId + ".html");
            try {
              int rc = executeAnchoreCommand(jenkinsLauncher, globalConfig,
                  "--html query --imagefile " + anchoreImageFile + " " + query.getQuery(), jenkinsQueryOutputFP.write());
              if (rc != 0) {
                // Record failure and move on to next query
                logWarn("Query execution failed for: " + query.getQuery() + ", return code: " + rc
                    + ". Recording the failure and moving on");
              } else {
                if (jenkinsQueryOutputFP.exists() && jenkinsQueryOutputFP.length() > 0) {
                  logDebug("Query execution completed successfully and generated a report for: " + query.getQuery());
                  jenkinsGeneratedOutput.put(queryId, jenkinsQueryOutputFP);
                  successfulQueries.put(queryId, query.getQuery());
                } else {
                  // Record failure and move on to next query
                  logWarn("Query execution completed successfully but did not generate a report for: " + query.getQuery());
                  jenkinsQueryOutputFP.delete();
                }
              }
            } catch (IOException | InterruptedException e) {
              // Record failure and move on to next query
              logWarn("Query execution failed for: " + query.getQuery() + ". Recording the failure and moving on", e);
            }
          } else {
            logWarn("Invalid or empty query found, skipping query execution");
          }
        }
      } else {
        logDebug("No queries found, skipping query execution");
      }
    } catch (RuntimeException e) {
      logError("Failed to run Anchore queries due to an unexpected error", e);
      throw new AbortException(
          "Failed to run Anchore queries due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void generateReports(AbstractBuild build, Map<String, FilePath> jenkinsGeneratedOutput,
      Map<String, String> successfulQueries) throws AbortException {
    try {
      logDebug("Generating reports");

      FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);

      // This is just for appending CSS style to anchore outputs. TODO there may be a better way of doing this, fix it!
      for (Map.Entry<String, FilePath> in : jenkinsGeneratedOutput.entrySet()) {
        FilePath inFile = in.getValue();
        if (inFile.exists() && inFile.length() > 0) {
          try (BufferedReader br = new BufferedReader(new InputStreamReader(inFile.read(), StandardCharsets.UTF_8))) {
            try (BufferedWriter bw = new BufferedWriter(
                new OutputStreamWriter(new FilePath(jenkinsOutputDirFP, in.getKey() + "_format.html").write(),
                    StandardCharsets.UTF_8))) {
              bw.write("<link rel=\"stylesheet\" type=\"text/css\" href=\"" + ANCHORE_CSS + "\">\n");
              Util.copyStreamAndClose(br, bw);
            }
          }
          inFile.delete();
        } else {
          logWarn("File not found or empty: " + in.getValue().getRemote());
        }
      }

      // add the link in jenkins UI for anchore results
      if (finalAction != null) {
        switch (finalAction) {
          case STOP:
            build.addAction(new AnchoreAction(build, "STOP", buildId, successfulQueries));
            break;
          case WARN:
            build.addAction(new AnchoreAction(build, "WARN", buildId, successfulQueries));
            break;
          case GO:
            build.addAction(new AnchoreAction(build, "GO", buildId, successfulQueries));
            break;
        }
      } else {
        build.addAction(new AnchoreAction(build, "", buildId, successfulQueries));
      }
    } catch (IOException | InterruptedException e) {
      logWarn("Unable to generate reports", e);
      throw new AbortException("Unable to generate reports due to " + e.getMessage());
    } catch (Exception e) {
      // caught unknown exception, log it and wrap it
      logError("Failed to run Anchore gates due to an unexpected error", e);
      throw new AbortException(
          "Failed to run Anchore gates due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void archiveReports(AbstractBuild build, Launcher jenkinsLauncher, BuildListener listener) throws AbortException {
    try {
      // store anchore output html files using jenkins archiver (for remote storage as well)
      logInfo("Archiving results");
      FilePath buildWorkspaceFP = build.getWorkspace();
      if (null != buildWorkspaceFP) {
        ArtifactArchiver artifactArchiver = new ArtifactArchiver(jenkinsOutputDirName + "/");
        artifactArchiver.perform(build, buildWorkspaceFP, jenkinsLauncher, listener);
      } else {
        logError("Unable to archive results due to an invalid reference to Jenkins build workspace");
        throw new AbortException("Unable to archive results due to an invalid reference to Jenkins build workspace");
      }
    } catch (AbortException e) {
      // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      // caught unknown exception, log it and wrap it
      logError("Failed to archive results due to an unexpected error", e);
      throw new AbortException(
          "Failed to archive results due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void cleanup(AbstractBuild build, Launcher jenkinsLauncher, DescriptorImpl globalConfig) {
    try {
      logDebug("Cleaning up build artifacts");
      int rc;

      // Clear Jenkins workspace
      if (!Strings.isNullOrEmpty(jenkinsOutputDirName)) {
        try {
          logDebug("Deleting Jenkins workspace " + jenkinsOutputDirName);
          FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
          jenkinsOutputDirFP.deleteRecursive();
        } catch (IOException | InterruptedException e) {
          logDebug("Unable to delete Jenkins workspace " + jenkinsOutputDirName, e);
        }
      }

      // Clear Anchore Container workspace
      if (!Strings.isNullOrEmpty(anchoreWorkspaceDirName)) {
        try {
          logDebug("Deleting Anchore container workspace " + anchoreWorkspaceDirName);
          rc = executeCommand(jenkinsLauncher, globalConfig,
              "docker exec " + globalConfig.getContainerId() + " rm -rf " + anchoreWorkspaceDirName);
          if (rc != 0) {
            logWarn("Unable to delete Anchore container workspace " + anchoreWorkspaceDirName + ", process returned " + rc);
          }
        } catch (Exception e) {
          logWarn("Failed to recursively delete Anchore container workspace " + anchoreWorkspaceDirName, e);
        }
      }

      if (doCleanup && null != anchoreInputImages) {
        for (String imageId : anchoreInputImages) {
          try {
            logDebug("Deleting analytics for " + imageId + " from Anchore database");
            rc = executeAnchoreCommand(jenkinsLauncher, globalConfig, "toolbox --image " + imageId + " delete --dontask");
            if (rc != 0) {
              logWarn("Failed to delete analytics for " + imageId + " from Anchore database, process returned " + rc);
            }
          } catch (Exception e) {
            logWarn("Failed to delete analytics for " + imageId + " from Anchore database", e);
          }
        }
      }
    } catch (RuntimeException e) {
      // caught unknown exception, log it and wrap it
      logDebug("Failed to clean up build artifacts due to an unexpected error", e);
    }
  }

  private void setupAnchoreContainer(Launcher jenkinsLauncher, DescriptorImpl globalConfig) throws AbortException {
    String containerId = globalConfig.getContainerId();

    if (!isAnchoreRunning(jenkinsLauncher, globalConfig)) {
      logDebug("Anchore container " + containerId + " is not running");
      String containerImageId = globalConfig.getContainerImageId();

      if (isAnchoreImageAvailable(jenkinsLauncher, globalConfig)) {
        logInfo("Launching Anchore container " + containerId + " from image " + containerImageId);

        String cmd = "docker run -d -v /var/run/docker.sock:/var/run/docker.sock";
        if (!Strings.isNullOrEmpty(globalConfig.localVol)) {
          cmd = cmd + " -v " + globalConfig.localVol + ":/root/.anchore";
        }

        if (!Strings.isNullOrEmpty(globalConfig.getModulesVol())) {
          cmd = cmd + " -v " + globalConfig.getModulesVol() + ":/root/anchore_modules";
        }
        cmd = cmd + " --name " + containerId + " " + containerImageId;

        int rc = executeCommand(jenkinsLauncher, globalConfig, cmd);

        if (rc == 0) {
          logDebug("Anchore container " + containerId + " has been launched");
        } else {
          logError("Failed to launch Anchore container " + containerId + " ");
          throw new AbortException("Failed to launch Anchore container " + containerId);
        }

      } else {
        // image is not available
        logError("Anchore container image " + containerImageId + " not found on local dockerhost, cannot launch Anchore container "
            + containerId);
        throw new AbortException(
            "Anchore container image " + containerImageId + " not found on local dockerhost, cannot launch Anchore container "
                + containerId + ". Please make the anchore/jenkins image available to the local dockerhost and retry");
      }
    } else {
      logDebug("Anchore container " + containerId + " is already running");
    }
  }

  private boolean isAnchoreRunning(Launcher jenkinsLauncher, DescriptorImpl globalConfig) throws AbortException {
    logDebug("Checking container " + globalConfig.getContainerId());
    if (!Strings.isNullOrEmpty(globalConfig.getContainerId())) {
      if (executeCommand(jenkinsLauncher, globalConfig, "docker start " + globalConfig.getContainerId()) != 0) {
        return false;
      } else {
        return true;
      }
    } else {
      logError("Anchore Container ID not found");
      throw new AbortException(
          "Please configure \"Anchore Container ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry. If the"
              + " container is not running, the plugin will launch it");
    }
  }

  private boolean isAnchoreImageAvailable(Launcher jenkinsLauncher, DescriptorImpl globalConfig) throws AbortException {
    logDebug("Checking container image " + globalConfig.getContainerImageId());
    if (!Strings.isNullOrEmpty(globalConfig.getContainerImageId())) {
      if (executeCommand(jenkinsLauncher, globalConfig, "docker inspect " + globalConfig.getContainerImageId()) != 0) {
        return false;
      } else {
        return true;
      }
    } else {
      logError("Anchore Container Image ID not found");
      throw new AbortException(
          "Please configure \"Anchore Container Image ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry.");
    }
  }

  private int executeCommand(Launcher jenkinsLauncher, DescriptorImpl globalConfig, String cmd) throws AbortException {
    // log stdout to console only if debug is turned on
    // always log stderr to console
    return executeCommand(jenkinsLauncher, globalConfig, cmd, globalConfig.getDebug() ? buildLog : null, buildLog);
  }

  private int executeCommand(Launcher jenkinsLauncher, DescriptorImpl globalConfig, String cmd, OutputStream out, OutputStream error)
      throws AbortException {
    int rc;

    if (globalConfig.getUseSudo()) {
      cmd = "sudo " + cmd;
    }

    Launcher.ProcStarter ps = jenkinsLauncher.launch();
    ps.cmdAsSingleString(cmd);
    ps.stdin(null);
    if (null != out) {
      ps.stdout(out);
    }
    if (null != error) {
      ps.stderr(error);
    }

    try {
      logDebug("Executing \"" + cmd + "\"");
      rc = ps.join();
      logDebug("Execution of \"" + cmd + "\" returned " + rc);
      return rc;
    } catch (Exception e) {
      logWarn("Failed to execute \"" + cmd + "\"", e);
      throw new AbortException("Failed to execute \"" + cmd + "\"");
    }
  }

  private int executeAnchoreCommand(Launcher jenkinsLauncher, DescriptorImpl globalConfig, String cmd) throws AbortException {
    return executeAnchoreCommand(jenkinsLauncher, globalConfig, cmd, globalConfig.getDebug() ? buildLog : null, buildLog);
  }

  private int executeAnchoreCommand(Launcher jenkinsLauncher, DescriptorImpl globalConfig, String cmd, OutputStream out)
      throws AbortException {
    return executeAnchoreCommand(jenkinsLauncher, globalConfig, cmd, out, buildLog);
  }

  /**
   * Helper for executing Anchore CLI. Abstracts docker and debug options out for the caller
   */
  private int executeAnchoreCommand(Launcher jenkinsLauncher, DescriptorImpl globalConfig, String cmd, OutputStream out,
      OutputStream error) throws AbortException {
    String dockerCmd = "docker exec " + globalConfig.getContainerId() + " " + ANCHORE_BINARY;

    if (globalConfig.getDebug()) {
      dockerCmd += " --debug";
    }

    if (!Strings.isNullOrEmpty(anchoreScriptsDirName)) {
      dockerCmd += " --config-override user_scripts_dir=" + anchoreScriptsDirName;
    }

    dockerCmd += " " + cmd;

    return executeCommand(jenkinsLauncher, globalConfig, dockerCmd, out, error);
  }

  private void logDebug(String msg) {
    if (enableDebug) {
      buildLog.println(String.format(LOG_FORMAT, new Date(), "DEBUG", msg));
    }
  }

  private void logDebug(String msg, Throwable t) {
    logDebug(msg);
    if (null != t) {
      t.printStackTrace(buildLog);
    }
  }

  private void logInfo(String msg) {
    buildLog.println(String.format(LOG_FORMAT, new Date(), "INFO", msg));
  }

  private void logWarn(String msg) {
    buildLog.println(String.format(LOG_FORMAT, new Date(), "WARN", msg));
  }

  private void logWarn(String msg, Throwable t) {
    logWarn(msg);
    if (null != t) {
      t.printStackTrace(buildLog);
    }
  }

  private void logError(String msg) {
    buildLog.println(String.format(LOG_FORMAT, new Date(), "ERROR", msg));
  }

  private void logError(String msg, Throwable t) {
    logError(msg);
    if (null != t) {
      t.printStackTrace(buildLog);
    }
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

