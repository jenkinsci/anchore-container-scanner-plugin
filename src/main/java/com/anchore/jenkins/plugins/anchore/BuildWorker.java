package com.anchore.jenkins.plugins.anchore;

import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.google.common.base.Strings;
import hudson.AbortException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.PluginWrapper;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Node;
import hudson.tasks.ArtifactArchiver;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import jenkins.model.Jenkins;

/**
 * A helper class to ensure concurrent jobs don't step on each other's toes. Anchore plugin instantiates a new instance of this class
 * for each individual job i.e. invocation of perform(). This is separate from the Jenkins Databound Constructor. Global and project
 * configuration at the time of execution is loaded into worker instance via its constructor. That specific worker instance is
 * responsible for the bulk of the plugin operations for a given job.
 */
public class BuildWorker {

  private static final Logger LOG = Logger.getLogger(BuildWorker.class.getName());

  // TODO refactor
  private static final String ANCHORE_BINARY = "anchore";
  private static final String GATES_OUTPUT_PREFIX = "anchore_gates";
  private static final String QUERY_OUTPUT_PREFIX = "anchore_query_";
  private static final String JENKINS_DIR_NAME_PREFIX = "AnchoreReport.";
  private static final String JSON_FILE_EXTENSION = ".json";

  // Private members
  AbstractBuild build;
  Launcher launcher;
  BuildListener listener;
  BuildConfig config;


  /* Initialized by the constructor */
  private ConsoleLog console; // Log handler for logging to build console
  private boolean analyzed;

  // Initialized by Jenkins workspace prep
  private String buildId;
  private String jenkinsOutputDirName;
  private Map<String, String> queryOutputMap; // TODO rename
  private String gateOutputFileName;
  private GATE_ACTION finalAction;

  // Initialized by Anchore workspace prep
  private String anchoreWorkspaceDirName;
  private String anchoreImageFileName; //TODO rename
  private String anchorePolicyFileName;
  private String anchoreScriptsDirName;
  private List<String> anchoreInputImages;

  public BuildWorker(AbstractBuild build, Launcher launcher, BuildListener listener, BuildConfig config) throws AbortException {
    try {

      // Verify and initialize build listener
      if (null != listener) {
        this.listener = listener;
      } else {
        LOG.warning("Anchore Container Image Scanner plugin cannot initialize Jenkins build listener");
        throw new AbortException("Cannot initialize Jenkins build listener. Aborting build step");
      }

      // Verify and initialize configuration
      if (null != config) {
        this.config = config;
      } else {
        LOG.warning("Anchore Container Image Scanner plugin does not have the configuration to execute build step");
        throw new AbortException(
            "Configuration for the plugin is invalid. Configure the plugin under Manage Jenkins->Configure System->Anchore "
                + "Configuration first. Add the Anchore Container Image Scanner build step in your project and retry");
      }

      // Initialize build logger to log output to consoleLog, use local logging methods only after this initializer completes
      console = new ConsoleLog("AnchoreWorker", this.listener.getLogger(), this.config.getDebug());

      // Verify and initialize Jenkins launcher for executing processes
      // TODO is this necessary? Can't we use the launcher reference that was passed in
      Node jenkinsNode = build.getBuiltOn();
      if (null != jenkinsNode) {
        this.launcher = jenkinsNode.createLauncher(listener);
        if (null == this.launcher) {
          console.logError("Cannot initialize Jenkins process executor");
          throw new AbortException("Cannot initialize Jenkins process executor. Aborting build step");
        }
      } else {
        console.logError("Cannot access Jenkins node running the build");
        throw new AbortException("Cannot access Jenkins node running the build. Aborting build step");
      }

      // Initialize build
      this.build = build;

      // Initialize analyzed flag to false to indicate that analysis step has not run
      this.analyzed = false;

      // Print versions and build configuration
      printConfig();

      // Check config
      checkConfig();

      // Initialize Jenkins workspace
      initializeJenkinsWorkspace();

      // Initialize Anchore workspace
      initializeAnchoreWorkspace();

      console.logDebug("Build worker initialized");
    } catch (Exception e) {
      try {
        if (console != null) {
          console.logError("Failed to initialize worker for plugin execution, check logs for corrective action");
        }
        cleanJenkinsWorkspaceQuietly();
        cleanAnchoreWorkspaceQuietly();
      } finally {
        if (e instanceof AbortException) {
          throw e;
        } else {
          throw new AbortException("Failed to initialize worker for plugin execution, check the logs for corrective action");
        }
      }
    }
  }

  public void runAnalyzer() throws AbortException {
    try {
      console.logInfo("Running Anchore Analyzer");

      int rc = executeAnchoreCommand("analyze --imagefile " + anchoreImageFileName);
      if (rc != 0) {
        console.logError("Anchore analyzer failed with return code " + rc + ", check output above for details");
        throw new AbortException("Anchore analyzer failed, check output above for details");
      }
      console.logDebug("Anchore analyzer completed successfully");
      analyzed = true;
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) { // caught unknown exception, log it and wrap its
      console.logError("Failed to run Anchore analyzer due to an unexpected error", e);
      throw new AbortException(
          "Failed to run Anchore analyzer due to an unexpected error. Please refer to above logs for more information");
    }
  }

  public GATE_ACTION runGates() throws AbortException {
    if (analyzed) {
      try {
        console.logInfo("Running Anchore Gates");

        FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
        FilePath jenkinsGatesOutputFP = new FilePath(jenkinsOutputDirFP, gateOutputFileName);
        String cmd = "--json gate --imagefile " + anchoreImageFileName;

        if (!Strings.isNullOrEmpty(anchorePolicyFileName)) {
          cmd += " --policy " + anchorePolicyFileName;
        }

        try {
          int rc = executeAnchoreCommand(cmd, jenkinsGatesOutputFP.write());
          switch (rc) {
            case 0:
              finalAction = Util.GATE_ACTION.GO;
              break;
            case 2:
              finalAction = Util.GATE_ACTION.WARN;
              break;
            default:
              finalAction = Util.GATE_ACTION.STOP;
          }

          console.logDebug("Anchore gate execution completed successfully, final action: " + finalAction);

          return finalAction;
        } catch (IOException | InterruptedException e) {
          console.logWarn("Failed to write gates output to " + jenkinsGatesOutputFP.getRemote(), e);
          throw new AbortException("Failed to write gates output to " + jenkinsGatesOutputFP.getRemote());
        }
      } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
        throw e;
      } catch (Exception e) { // caught unknown exception, log it and wrap it
        console.logError("Failed to run Anchore gates due to an unexpected error", e);
        throw new AbortException(
            "Failed to run Anchore gates due to an unexpected error. Please refer to above logs for more information");
      }
    } else {
      console.logError("Analysis step has not been executed (or may have failed in a prior attempt). Rerun analyzer before gates");
      throw new AbortException(
          "Analysis step has not been executed (or may have failed in a prior attempt). Rerun analyzer before gates");
    }
  }

  public void runQueries() throws AbortException {
    if (analyzed) {
      try {
        if (config.getInputQueries() != null && !config.getInputQueries().isEmpty()) {
          int key = 0;
          for (AnchoreQuery entry : config.getInputQueries()) {
            String query = entry.getQuery().trim();
            if (!Strings.isNullOrEmpty(query) && !queryOutputMap.containsKey(query)) {

              console.logInfo("Running Anchore Query: " + query);
              String queryOutputFileName = QUERY_OUTPUT_PREFIX + (++key) + JSON_FILE_EXTENSION;
              FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
              FilePath jenkinsQueryOutputFP = new FilePath(jenkinsOutputDirFP, queryOutputFileName);

              try {
                int rc = executeAnchoreCommand("--json query --imagefile " + anchoreImageFileName + " " + query,
                    jenkinsQueryOutputFP.write());
                if (rc != 0) {
                  // Record failure and move on to next query
                  console.logWarn("Query execution failed for: " + query + ", return code: " + rc);
                } else {
                  if (jenkinsQueryOutputFP.exists() && jenkinsQueryOutputFP.length() > 0) {
                    console.logDebug("Query execution completed successfully and generated a report for: " + query);
                    queryOutputMap.put(query, queryOutputFileName);
                  } else {
                    // Record failure and move on to next query
                    console.logWarn("Query execution completed successfully but did not generate a report for: " + query);
                    jenkinsQueryOutputFP.delete();
                  }
                }
              } catch (IOException | InterruptedException e) {
                // Record failure and move on to next query
                console.logWarn("Query execution failed for: " + query, e);
              }

            } else {
              console.logWarn("Invalid query or query may have already been executed");
            }
          }
        } else {
          console.logDebug("No queries found, skipping query execution");
        }
      } catch (RuntimeException e) {
        console.logError("Failed to run Anchore queries due to an unexpected error", e);
        throw new AbortException(
            "Failed to run Anchore queries due to an unexpected error. Please refer to above logs for more information");
      }
    } else {
      console.logError("Analysis step has not been executed (or may have failed in a prior attempt). Rerun analyzer before queries");
      throw new AbortException(
          "Analysis step has not been executed (or may have failed in a prior attempt). Rerun analyzer before queries");
    }
  }

  public void setupBuildReports() throws AbortException {
    try {
      // store anchore output json files using jenkins archiver (for remote storage as well)
      console.logInfo("Archiving results");
      FilePath buildWorkspaceFP = build.getWorkspace();
      if (null != buildWorkspaceFP) {
        ArtifactArchiver artifactArchiver = new ArtifactArchiver(jenkinsOutputDirName + "/");
        artifactArchiver.perform(build, buildWorkspaceFP, launcher, listener);
      } else {
        console.logError("Unable to archive results due to an invalid reference to Jenkins build workspace");
        throw new AbortException("Unable to archive results due to an invalid reference to Jenkins build workspace");
      }

      // add the link in jenkins UI for anchore results
      console.logDebug("Setting up build results");

      if (finalAction != null) {
        switch (finalAction) {
          case STOP:
            build.addAction(new AnchoreAction(build, "STOP", jenkinsOutputDirName, gateOutputFileName, queryOutputMap));
            break;
          case WARN:
            build.addAction(new AnchoreAction(build, "WARN", jenkinsOutputDirName, gateOutputFileName, queryOutputMap));
            break;
          case GO:
            build.addAction(new AnchoreAction(build, "GO", jenkinsOutputDirName, gateOutputFileName, queryOutputMap));
            break;
        }
      } else {
        build.addAction(new AnchoreAction(build, "", jenkinsOutputDirName, gateOutputFileName, queryOutputMap));
      }
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) { // caught unknown exception, log it and wrap it
      console.logError("Failed to setup build results due to an unexpected error", e);
      throw new AbortException(
          "Failed to setup build results due to an unexpected error. Please refer to above logs for more information");
    }
  }

  public void cleanup() {
    try {
      console.logDebug("Cleaning up build artifacts");
      int rc;

      // Clear Jenkins workspace
      if (!Strings.isNullOrEmpty(jenkinsOutputDirName)) {
        try {
          console.logDebug("Deleting Jenkins workspace " + jenkinsOutputDirName);
          cleanJenkinsWorkspaceQuietly();
          // FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
          // jenkinsOutputDirFP.deleteRecursive();
        } catch (IOException | InterruptedException e) {
          console.logDebug("Unable to delete Jenkins workspace " + jenkinsOutputDirName, e);
        }
      }

      // Clear Anchore Container workspace
      if (!Strings.isNullOrEmpty(anchoreWorkspaceDirName)) {
        try {
          console.logDebug("Deleting Anchore container workspace " + anchoreWorkspaceDirName);
          rc = cleanAnchoreWorkspaceQuietly();
          // rc = executeCommand("docker exec " + config.getContainerId() + " rm -rf " + anchoreWorkspaceDirName);
          if (rc != 0) {
            console.logWarn("Unable to delete Anchore container workspace " + anchoreWorkspaceDirName + ", process returned " + rc);
          }
        } catch (Exception e) {
          console.logWarn("Failed to recursively delete Anchore container workspace " + anchoreWorkspaceDirName, e);
        }
      }

      if (config.getDoCleanup() && null != anchoreInputImages) {
        for (String imageId : anchoreInputImages) {
          try {
            console.logDebug("Deleting analytics for " + imageId + " from Anchore database");
            rc = executeAnchoreCommand("toolbox --image " + imageId + " delete --dontask");
            if (rc != 0) {
              console.logWarn("Failed to delete analytics for " + imageId + " from Anchore database, process returned " + rc);
            }
          } catch (Exception e) {
            console.logWarn("Failed to delete analytics for " + imageId + " from Anchore database", e);
          }
        }
      }
    } catch (RuntimeException e) { // caught unknown exception, log it
      console.logDebug("Failed to clean up build artifacts due to an unexpected error", e);
    }
  }

  /**
   * Print versions info and configuration
   */
  private void printConfig() {
    console.logInfo("Jenkins version: " + Jenkins.VERSION);
    List<PluginWrapper> plugins;
    if (Jenkins.getActiveInstance() != null && Jenkins.getActiveInstance().getPluginManager() != null
        && (plugins = Jenkins.getActiveInstance().getPluginManager().getPlugins()) != null) {
      for (PluginWrapper plugin : plugins) {
        if (plugin.getShortName()
            .equals("anchore-container-scanner")) { // artifact ID of the plugin, TODO is there a better way to get this
          console.logInfo(plugin.getDisplayName() + " version: " + plugin.getVersion());
          break;
        }
      }
    }
    config.print(console);
  }

  /**
   * Checks for minimum required config for executing build step
   */
  private void checkConfig() throws AbortException {
    if (!config.getEnabled()) {
      console.logError("Anchore image scanning is disabled");
      throw new AbortException(
          "Anchore image scanning is disabled. Please enable image scanning in Anchore Configuration under Manage Jenkins -> "
              + "Configure System and try again");
    }

    if (Strings.isNullOrEmpty(config.getName())) {
      console.logError("Image list file not found");
      throw new AbortException(
          "Image list file not specified. Please specify a valid image list file name in the Anchore plugin build step "
              + "configuration and try again");
    }

    try {
      if (!new FilePath(build.getWorkspace(), config.getName()).exists()) {
        console.logError("Cannot find image list file \"" + config.getName() + "\" under " + build.getWorkspace());
        throw new AbortException("Cannot find image list file \'" + config.getName()
            + "\'. Please ensure that image list file is created prior to Anchore Container Image Scanner build step");
      }
    } catch (AbortException e) {
      throw e;
    } catch (Exception e) {
      console.logWarn("Unable to access image list file \"" + config.getName() + "\" under " + build.getWorkspace(), e);
      throw new AbortException("Unable to access image list file " + config.getName()
          + ". Please ensure that image list file is created prior to Anchore Container Image Scanner build step");
    }

    if (Strings.isNullOrEmpty(config.getContainerId())) {
      console.logError("Anchore Container ID not found");
      throw new AbortException(
          "Please configure \"Anchore Container ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry. If the"
              + " container is not running, the plugin will launch it");
    }

    // TODO docker and image checks necessary here? check with Dan

  }

  private void initializeJenkinsWorkspace() throws AbortException {
    try {
      console.logDebug("Initializing Jenkins workspace");

      if (Strings.isNullOrEmpty(buildId = build.getParent().getDisplayName() + "_" + build.getNumber())) {
        console.logWarn("Unable to generate a unique identifier for this build due to invalid configuration");
        throw new AbortException("Unable to generate a unique identifier for this build due to invalid configuration");
      }

      jenkinsOutputDirName = JENKINS_DIR_NAME_PREFIX + buildId;
      FilePath jenkinsReportDir = new FilePath(build.getWorkspace(), jenkinsOutputDirName);

      // Create output directories
      if (!jenkinsReportDir.exists()) {
        console.logDebug("Creating workspace directory " + jenkinsOutputDirName);
        jenkinsReportDir.mkdirs();
      }

      queryOutputMap = new LinkedHashMap<>(); // maintain the ordering of queries
      gateOutputFileName = GATES_OUTPUT_PREFIX + JSON_FILE_EXTENSION;

    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) { // caught unknown exception, log it and wrap it
      console.logWarn("Failed to initialize Jenkins workspace", e);
      throw new AbortException("Failed to initialize Jenkins workspace due to to an unexpected error");
    }
  }

  private void initializeAnchoreWorkspace() throws AbortException {
    try {
      console.logDebug("Initializing Anchore workspace");

      // Setup the container first
      setupAnchoreContainer();

      // Initialize anchore workspace variables
      anchoreWorkspaceDirName = "/root/anchore." + buildId;
      anchoreImageFileName = anchoreWorkspaceDirName + "/images";
      anchoreInputImages = new ArrayList<>();

      // setup staging directory in anchore container
      console.logDebug(
          "Creating build artifact directory " + anchoreWorkspaceDirName + " in Anchore container " + config.getContainerId());
      int rc = executeCommand("docker exec " + config.getContainerId() + " mkdir -p " + anchoreWorkspaceDirName);
      if (rc != 0) {
        console.logError("Failed to create build artifact directory " + anchoreWorkspaceDirName + " in Anchore container " + config
            .getContainerId());
        throw new AbortException(
            "Failed to create build artifact directory " + anchoreWorkspaceDirName + " in Anchore container " + config
                .getContainerId());
      }

      // Sanitize the input image list
      // - Copy dockerfile for images to anchore container
      // - Create a staging file with adjusted paths
      console.logDebug("Staging image file in Jenkins workspace");

      FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
      FilePath jenkinsStagedImageFP = new FilePath(jenkinsOutputDirFP, "staged_images." + buildId);
      FilePath inputImageFP = new FilePath(build.getWorkspace(), config.getName()); // Already checked in checkConfig()

      try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsStagedImageFP.write(), StandardCharsets.UTF_8))) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputImageFP.read(), StandardCharsets.UTF_8))) {
          String line;
          int count = 0;
          while ((line = br.readLine()) != null) {
            // TODO check for a later libriary of guava that lets your slit strings into a list
            Iterable<String> iterable = Util.IMAGE_LIST_SPLITTER.split(line);
            Iterator<String> partIterator;

            if (null != iterable && null != (partIterator = iterable.iterator()) && partIterator.hasNext()) {
              String imgId = partIterator.next();
              String lineToBeAdded = imgId;

              if (partIterator.hasNext()) {
                String jenkinsDFile = partIterator.next();
                String anchoreDFile = anchoreWorkspaceDirName + "/dfile." + (++count);

                // Copy file from Jenkins to Anchore container
                console.logDebug(
                    "Copying Dockerfile from Jenkins workspace: " + jenkinsDFile + ", to Anchore workspace: " + anchoreDFile);
                rc = executeCommand("docker cp " + jenkinsDFile + " " + config.getContainerId() + ":" + anchoreDFile);
                if (rc != 0) {
                  // TODO check with Dan if operation should continue for other images
                  console.logError(
                      "Failed to copy Dockerfile from Jenkins workspace: " + jenkinsDFile + ", to Anchore workspace: " + anchoreDFile);
                  throw new AbortException(
                      "Failed to copy Dockerfile from Jenkins workspace: " + jenkinsDFile + ", to Anchore workspace: " + anchoreDFile
                          + ". Please ensure that Dockerfile is present in the Jenkins workspace prior to running Anchore plugin");
                }
                lineToBeAdded += " " + anchoreDFile;
              } else {
                console
                    .logWarn("No dockerfile specified for image " + imgId + ". Anchore analyzer will attempt to construct dockerfile");
              }

              console.logDebug("Staging sanitized entry: \"" + lineToBeAdded + "\"");

              lineToBeAdded += "\n";

              bw.write(lineToBeAdded);
              anchoreInputImages.add(imgId);
            } else {
              console.logWarn("Cannot parse: \"" + line
                  + "\". Format for each line in input image file is \"imageId /path/to/Dockerfile\", where the Dockerfile is "
                  + "optional");
            }
          }
        }
      }

      if (anchoreInputImages.isEmpty()) {
        // nothing to analyze here
        console.logError("List of input images to be analyzed is empty");
        throw new AbortException(
            "List of input images to be analyzed is empty. Please ensure that image file is populated with a list of images to be "
                + "analyzed. " + "Format for each line is \"imageId /path/to/Dockerfile\", where the Dockerfile is optional");
      }

      // finally, stage the rest of the files

      // Copy the staged images file from Jenkins workspace to Anchore container
      console.logDebug(
          "Copying staged image file from Jenkins workspace: " + jenkinsStagedImageFP.getRemote() + ", to Anchore workspace: "
              + anchoreImageFileName);
      rc = executeCommand(
          "docker cp " + jenkinsStagedImageFP.getRemote() + " " + config.getContainerId() + ":" + anchoreImageFileName);
      if (rc != 0) {
        console.logError(
            "Failed to copy staged image file from Jenkins workspace: " + jenkinsStagedImageFP.getRemote() + ", to Anchore workspace: "
                + anchoreImageFileName);
        throw new AbortException(
            "Failed to copy staged image file from Jenkins workspace: " + jenkinsStagedImageFP.getRemote() + ", to Anchore workspace: "
                + anchoreImageFileName);
      }

      // Copy the user scripts directory from Jenkins workspace to Anchore container
      try {
        FilePath jenkinsScriptsDir;
        if (!Strings.isNullOrEmpty(config.getUserScripts()) && (jenkinsScriptsDir = new FilePath(build.getWorkspace(),
            config.getUserScripts())).exists()) {
          anchoreScriptsDirName = anchoreWorkspaceDirName + "/anchorescripts/";
          console.logDebug("Copying user scripts from Jenkins workspace: " + jenkinsScriptsDir.getRemote() + ", to Anchore workspace: "
              + anchoreScriptsDirName);
          rc = executeCommand(
              "docker cp " + jenkinsScriptsDir.getRemote() + " " + config.getContainerId() + ":" + anchoreScriptsDirName);
          if (rc != 0) {
            // TODO Check with Dan if we should abort here
            console.logWarn(
                "Failed to copy user scripts from Jenkins workspace: " + jenkinsScriptsDir.getRemote() + ", to Anchore workspace: "
                    + anchoreScriptsDirName + ". Using default Anchore modules");
            anchoreScriptsDirName = null; // reset it so it doesn't get used later
            // throw new AbortException(
            //    "Failed to copy user scripts from Jenkins workspace: " + jenkinsScriptsDir.getRemote() + ", to Anchore workspace: "
            //        + anchoreScriptsDirName);
          }
        } else {
          console.logDebug("No user scripts/modules found, using default Anchore modules");
        }
      } catch (IOException | InterruptedException e) {
        console.logWarn("Failed to resolve user modules, using default Anchore modules");
      }

      // Copy the policy file from Jenkins workspace to Anchore container
      try {
        FilePath jenkinsPolicyFile;
        if (!Strings.isNullOrEmpty(config.getPolicyName()) && (jenkinsPolicyFile = new FilePath(build.getWorkspace(),
            config.getPolicyName())).exists()) {
          anchorePolicyFileName = anchoreWorkspaceDirName + "/policy";
          console.logDebug("Copying policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
              + anchorePolicyFileName);

          rc = executeCommand(
              "docker cp " + jenkinsPolicyFile.getRemote() + " " + config.getContainerId() + ":" + anchorePolicyFileName);
          if (rc != 0) {
            // TODO check with Dan if we should abort here
            console.logWarn(
                "Failed to copy policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
                    + anchorePolicyFileName + ". Using default Anchore policy");
            anchorePolicyFileName = null; // reset it so it doesn't get used later
            // throw new AbortException(
            //    "Failed to copy policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
            //        + anchorePolicyFileName);
          }
        } else {
          console.logInfo("Policy file either not specified or does not exist, using default Anchore policy");
        }
      } catch (IOException | InterruptedException e) {
        console.logWarn("Failed to resolve user policy, using default Anchore policy");
      }
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) { // caught unknown exception, console.log it and wrap it
      console.logError("Failed to initialize Anchore workspace due to an unexpected error", e);
      throw new AbortException(
          "Failed to initialize Anchore workspace due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void setupAnchoreContainer() throws AbortException {
    String containerId = config.getContainerId();

    if (!isAnchoreRunning()) {
      console.logDebug("Anchore container " + containerId + " is not running");
      String containerImageId = config.getContainerImageId();

      if (isAnchoreImageAvailable()) {
        console.logInfo("Launching Anchore container " + containerId + " from image " + containerImageId);

        String cmd = "docker run -d -v /var/run/docker.sock:/var/run/docker.sock";
        if (!Strings.isNullOrEmpty(config.getLocalVol())) {
          cmd = cmd + " -v " + config.getLocalVol() + ":/root/.anchore";
        }

        if (!Strings.isNullOrEmpty(config.getModulesVol())) {
          cmd = cmd + " -v " + config.getModulesVol() + ":/root/anchore_modules";
        }
        cmd = cmd + " --name " + containerId + " " + containerImageId;

        int rc = executeCommand(cmd);

        if (rc == 0) {
          console.logDebug("Anchore container " + containerId + " has been launched");
        } else {
          console.logError("Failed to launch Anchore container " + containerId + " ");
          throw new AbortException("Failed to launch Anchore container " + containerId);
        }

      } else { // image is not available
        console.logError(
            "Anchore container image " + containerImageId + " not found on local dockerhost, cannot launch Anchore container "
                + containerId);
        throw new AbortException(
            "Anchore container image " + containerImageId + " not found on local dockerhost, cannot launch Anchore container "
                + containerId + ". Please make the anchore/jenkins image available to the local dockerhost and retry");
      }
    } else {
      console.logDebug("Anchore container " + containerId + " is already running");
    }
  }

  private boolean isAnchoreRunning() throws AbortException {
    console.logDebug("Checking container " + config.getContainerId());
    if (!Strings.isNullOrEmpty(config.getContainerId())) {
      if (executeCommand("docker start " + config.getContainerId()) != 0) {
        return false;
      } else {
        return true;
      }
    } else {
      console.logError("Anchore Container ID not found");
      throw new AbortException(
          "Please configure \"Anchore Container ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry. If the"
              + " container is not running, the plugin will launch it");
    }
  }

  private boolean isAnchoreImageAvailable() throws AbortException {
    console.logDebug("Checking container image " + config.getContainerImageId());
    if (!Strings.isNullOrEmpty(config.getContainerImageId())) {
      if (executeCommand("docker inspect " + config.getContainerImageId()) != 0) {
        return false;
      } else {
        return true;
      }
    } else {
      console.logError("Anchore Container Image ID not found");
      throw new AbortException(
          "Please configure \"Anchore Container Image ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry.");
    }
  }

  private int executeAnchoreCommand(String cmd) throws AbortException {
    return executeAnchoreCommand(cmd, config.getDebug() ? console.getLogger() : null, console.getLogger());
  }

  private int executeAnchoreCommand(String cmd, OutputStream out) throws AbortException {
    return executeAnchoreCommand(cmd, out, console.getLogger());
  }

  /**
   * Helper for executing Anchore CLI. Abstracts docker and debug options out for the caller
   */
  private int executeAnchoreCommand(String cmd, OutputStream out, OutputStream error) throws AbortException {
    String dockerCmd = "docker exec " + config.getContainerId() + " " + ANCHORE_BINARY;

    if (config.getDebug()) {
      dockerCmd += " --debug";
    }

    if (!Strings.isNullOrEmpty(anchoreScriptsDirName)) {
      dockerCmd += " --config-override user_scripts_dir=" + anchoreScriptsDirName;
    }

    dockerCmd += " " + cmd;

    return executeCommand(dockerCmd, out, error);
  }

  private int executeCommand(String cmd) throws AbortException {
    // log stdout to console only if debug is turned on
    // always log stderr to console
    return executeCommand(cmd, config.getDebug() ? console.getLogger() : null, console.getLogger());
  }

  private int executeCommand(String cmd, OutputStream out, OutputStream error) throws AbortException {
    int rc;

    if (config.getUseSudo()) {
      cmd = "sudo " + cmd;
    }

    Launcher.ProcStarter ps = launcher.launch();
    ps.cmdAsSingleString(cmd);
    ps.stdin(null);
    if (null != out) {
      ps.stdout(out);
    }
    if (null != error) {
      ps.stderr(error);
    }

    try {
      console.logDebug("Executing \"" + cmd + "\"");
      rc = ps.join();
      console.logDebug("Execution of \"" + cmd + "\" returned " + rc);
      return rc;
    } catch (Exception e) {
      console.logWarn("Failed to execute \"" + cmd + "\"", e);
      throw new AbortException("Failed to execute \"" + cmd + "\"");
    }
  }

  private void cleanJenkinsWorkspaceQuietly() throws IOException, InterruptedException {
    FilePath jenkinsOutputDirFP = new FilePath(build.getWorkspace(), jenkinsOutputDirName);
    jenkinsOutputDirFP.deleteRecursive();
  }

  private int cleanAnchoreWorkspaceQuietly() throws AbortException {
    return executeCommand("docker exec " + config.getContainerId() + " rm -rf " + anchoreWorkspaceDirName);
  }
}
