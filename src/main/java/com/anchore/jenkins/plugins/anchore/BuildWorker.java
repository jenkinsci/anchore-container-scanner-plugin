package com.anchore.jenkins.plugins.anchore;

import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.anchore.jenkins.plugins.anchore.Util.GATE_SUMMARY_COLUMN;
import com.google.common.base.Strings;
import hudson.AbortException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.PluginWrapper;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

/**
 * A helper class to ensure concurrent jobs don't step on each other's toes. Anchore plugin instantiates a new instance of this class
 * for each individual job i.e. invocation of perform(). Global and project configuration at the time of execution is loaded into
 * worker instance via its constructor. That specific worker instance is responsible for the bulk of the plugin operations for a given
 * job.
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
  Run<?, ?> build;
  FilePath workspace;
  Launcher launcher;
  TaskListener listener;
  BuildConfig config;


  /* Initialized by the constructor */
  private ConsoleLog console; // Log handler for logging to build console
  private boolean analyzed;

  // Initialized by Jenkins workspace prep
  private String buildId;
  private String jenkinsOutputDirName;
  private Map<String, String> queryOutputMap; // TODO rename
  private Map<String, String> input_image_dfile = new HashMap<String, String>();
  private Map<String, String> input_image_imageDigest = new HashMap<String, String>();
  private String gateOutputFileName;
  private GATE_ACTION finalAction;
  private JSONObject gateSummary;

  // Initialized by Anchore workspace prep
  private String anchoreWorkspaceDirName;
  private String anchoreImageFileName; //TODO rename
  private String anchorePolicyFileName;
  private String anchoreGlobalWhiteListFileName;
  private String anchoreBundleFileName;
  private String anchoreScriptsDirName;
  private List<String> anchoreInputImages;

  public BuildWorker(Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener, BuildConfig config)
      throws AbortException {
    try {
      // Initialize build
      this.build = build;

      // Initialize workspace reference
      this.workspace = workspace;

      // Verify and initialize build listener
      if (null != listener) {
        this.listener = listener;
      } else {
        LOG.warning("Anchore Container Image Scanner plugin cannot initialize Jenkins task listener");
        throw new AbortException("Cannot initialize Jenkins task listener. Aborting step");
      }

      // Verify and initialize configuration
      if (null != config) {
        this.config = config;
      } else {
        LOG.warning("Anchore Container Image Scanner cannot find the required configuration");
        throw new AbortException(
            "Configuration for the plugin is invalid. Configure the plugin under Manage Jenkins->Configure System->Anchore "
                + "Configuration first. Add the Anchore Container Image Scanner step in your project and retry");
      }

      // Initialize build logger to log output to consoleLog, use local logging methods only after this initializer completes
      console = new ConsoleLog("AnchoreWorker", this.listener.getLogger(), this.config.getDebug());

      console.logDebug("Initializing build worker");

      // Verify and initialize Jenkins launcher for executing processes
      // TODO is this necessary? Can't we use the launcher reference that was passed in
      this.launcher = workspace.createLauncher(listener);
      //      Node jenkinsNode = build.getBuiltOn();
      //      if (null != jenkinsNode) {
      //        this.launcher = jenkinsNode.createLauncher(listener);
      //        if (null == this.launcher) {
      //          console.logError("Cannot initialize Jenkins process executor");
      //          throw new AbortException("Cannot initialize Jenkins process executor. Aborting step");
      //        }
      //      } else {
      //        console.logError("Cannot access Jenkins node running the build");
      //        throw new AbortException("Cannot access Jenkins node running the build. Aborting step");
      //      }

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
          console.logError("Failed to initialize worker for plugin execution", e);
        }
        cleanJenkinsWorkspaceQuietly();
        cleanAnchoreWorkspaceQuietly();
      } catch (Exception innere) {

      } finally {
        throw new AbortException("Failed to initialize worker for plugin execution, check logs for corrective action");
      }
    }
  }

  public void runAnalyzer() throws AbortException {
    if (config.getEnginemode().equals("anchoreengine")) {
      runAnalyzerEngine();
    } else {
      runAnalyzerLocal();
    }
  }

  private static CloseableHttpClient makeHttpClient(boolean verify) {
    CloseableHttpClient httpclient = null;
    if (verify) {
      httpclient = HttpClients.createDefault();
    } else {
      //SSLContextBuilder builder;

      //SSLConnectionSocketFactory sslsf=null;

      try {
        SSLContextBuilder builder = new SSLContextBuilder();
        builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(),
            SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
      } catch (Exception e) {
        System.out.println(e);
      }
    }
    return (httpclient);
  }

  private void runAnalyzerEngine() throws AbortException {
    String imageDigest = null;
    String username = config.getEngineuser();
    String password = config.getEnginepass();
    boolean sslverify = config.getEngineverify();

    CredentialsProvider credsProvider = new BasicCredentialsProvider();
    credsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
    HttpClientContext context = HttpClientContext.create();
    context.setCredentialsProvider(credsProvider);

    try {
      for (Map.Entry<String, String> entry : input_image_dfile.entrySet()) {
        String tag = entry.getKey();
        String dfile = entry.getValue();

        console.logDebug("Adding " + tag + " to anchore-engine for analysis");

        try (CloseableHttpClient httpclient = makeHttpClient(sslverify)) {
          // Prep POST request
          String theurl = config.getEngineurl().replaceAll("/+$", "") + "/images";

          JSONObject jsonBody = new JSONObject();
          jsonBody.put("tag", tag);
          if (null != dfile) {
            jsonBody.put("dockerfile", dfile);
          }
          String body = jsonBody.toString();

          HttpPost httppost = new HttpPost(theurl);
          httppost.addHeader("Content-Type", "application/json");
          httppost.setEntity(new StringEntity(body));

          console.logDebug("anchore-engine add image URL: " + theurl);
          console.logDebug("anchore-engine add image payload: " + body);

          try (CloseableHttpResponse response = httpclient.execute(httppost, context)) {
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 200) {
              String serverMessage = EntityUtils.toString(response.getEntity());
              console.logError(
                  "anchore-engine add image failed. URL: " + theurl + ", status: " + response.getStatusLine() + ", error: "
                      + serverMessage);
              throw new AbortException("Failed to analyze " + tag
                  + " due to error adding image to anchore-engine. Check above logs for errors from anchore-engine");
            } else {
              // Read the response body.
              String responseBody = EntityUtils.toString(response.getEntity());
              // TODO EntityUtils.consume(entity2);
              JSONArray respJson = JSONArray.fromObject(responseBody);
              imageDigest = JSONObject.fromObject(respJson.get(0)).getString("imageDigest");
              console.logInfo("Submitted " + tag + " to anchore-engine for analysis. Received image digest: " + imageDigest);
              input_image_imageDigest.put(tag, imageDigest);
            }
          } catch (Throwable e) {
            throw e;
          }
        } catch (Throwable e) {
          throw e;
        }
      }
      analyzed = true;
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) { // caught unknown exception, log it and wrap its
      console.logError("Failed to add image(s) to anchore-engine due to an unexpected error", e);
      throw new AbortException(
          "Failed to add image(s) to anchore-engine due to an unexpected error. Please refer to above logs for more information");
    }
  }

  private void runAnalyzerLocal() throws AbortException {
    try {
      console.logInfo("Running Anchore Analyzer");

      int rc = executeAnchoreCommand("analyze --skipgates --imagefile " + anchoreImageFileName);
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

  private void doAnchoreioLogin() throws AbortException {

    try {
      String cmd =
          "docker exec " + config.getContainerId() + " /bin/bash -c \"export ANCHOREPASS=$ANCHOREPASS && anchore login --user "
              + config.getAnchoreioUser() + "\"";
      int rc = executeCommand(cmd, "ANCHOREPASS=" + config.getAnchoreioPass());
      if (rc != 0) {
        console.logWarn("Failed to log in to anchore.io using specified credentials");
        throw new AbortException("Failed to log in to anchore.io using specified credentials");
      }
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      console.logWarn("Failed to log in to anchore.io using specified credentials");
      throw new AbortException("Failed to log in to anchore.io using specified credentials");
    }
  }

  private void doAnchoreioBundleSync() throws AbortException {

    try {
      String cmd = "--json policybundle sync";
      int rc = executeAnchoreCommand(cmd);
      if (rc != 0) {
        console.logWarn("Failed to sync your policy bundle from anchore.io");
        throw new AbortException("Failed to sync your policy bundle from anchore.io");
      }
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      console.logWarn("Failed to sync your policy bundle from anchore.io");
      throw new AbortException("Failed to sync your policy bundle from anchore.io");
    }
  }

  public GATE_ACTION runGates() throws AbortException {
    if (config.getEnginemode().equals("anchoreengine")) {
      return (runGatesEngine());
    } else {
      return (runGatesLocal());
    }
  }

  private GATE_ACTION runGatesEngine() throws AbortException {
    String username = config.getEngineuser();
    String password = config.getEnginepass();
    boolean sslverify = config.getEngineverify();

    CredentialsProvider credsProvider = new BasicCredentialsProvider();
    credsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
    HttpClientContext context = HttpClientContext.create();
    context.setCredentialsProvider(credsProvider);

    //Credentials defaultcreds = new UsernamePasswordCredentials(username, password);
    FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
    FilePath jenkinsGatesOutputFP = new FilePath(jenkinsOutputDirFP, gateOutputFileName);

    finalAction = GATE_ACTION.PASS;
    if (analyzed) {
      try {
        JSONObject gate_results = new JSONObject();

        for (Map.Entry<String, String> entry : input_image_imageDigest.entrySet()) {
          String tag = entry.getKey();
          String imageDigest = entry.getValue();

          console.logInfo("Waiting on anchore-engine to analyze " + tag + ". Polling status periodically");

          Boolean anchore_eval_status = false;
          String theurl =
              config.getEngineurl().replaceAll("/+$", "") + "/images/" + imageDigest + "/check?tag=" + tag + "&detail=true";

          if (!Strings.isNullOrEmpty(config.getPolicyBundleId())) {
            theurl += "&policyId=" + config.getPolicyBundleId();
          }
          console.logDebug("anchore-engine get policy evaluation URL: " + theurl);

          int tryCount = 0;
          int maxCount = Integer.parseInt(config.getEngineRetries());
          Boolean done = false;
          HttpGet httpget = new HttpGet(theurl);
          httpget.addHeader("Content-Type", "application/json");
          int statusCode;
          String serverMessage = null;
          boolean sleep = false;

          do { // try this at least once regardless what the retry count is
            if (sleep) {
              console.logDebug("Snoozing before retrying anchore-engine get policy evaluation");
              Thread.sleep(1000);
              sleep = false;
            }

            tryCount++;
            try (CloseableHttpClient httpclient = makeHttpClient(sslverify)) {
              console.logDebug("Attempting anchore-engine get policy evaluation (" + tryCount + "/" + maxCount + ")");

              try (CloseableHttpResponse response = httpclient.execute(httpget, context)) {
                statusCode = response.getStatusLine().getStatusCode();

                if (statusCode != 200) {
                  serverMessage = EntityUtils.toString(response.getEntity());
                  console.logDebug(
                      "anchore-engine get policy evaluation failed. URL: " + theurl + ", status: " + response.getStatusLine()
                          + ", error: " + serverMessage);
                  // Thread.sleep(1000); sleeping here keeps connection open. Unnecessary if the retries have been exhausted
                  sleep = true;
                } else {
                  // Read the response body.
                  String responseBody = EntityUtils.toString(response.getEntity());
                  // TODO EntityUtils.consume(entity2);
                  JSONArray respJson = JSONArray.fromObject(responseBody);
                  JSONObject tag_eval_obj = JSONObject.fromObject(JSONArray.fromObject(
                      JSONArray.fromObject(JSONObject.fromObject(JSONObject.fromObject(respJson.get(0)).getJSONObject(imageDigest))))
                      .get(0));
                  JSONArray tag_evals = null;
                  for (Object key : tag_eval_obj.keySet()) {
                    tag_evals = tag_eval_obj.getJSONArray((String) key);
                    break;
                  }
                  //JSONArray tag_evals = JSONObject.fromObject(JSONArray.fromObject(JSONArray.fromObject(JSONObject.fromObject
                  // (JSONObject.fromObject(respJson.get(0)).getJSONObject(imageDigest)))).get(0)).getJSONArray(tag);
                  if (null == tag_evals) {
                    throw new AbortException(
                        "Failed to analyze " + tag + " due to missing tag eval records in anchore-engine policy evaluation response");
                  }
                  if (tag_evals.size() < 1) {
                    // try again until we get an eval
                    console
                        .logDebug("anchore-engine get policy evaluation response contains no tag eval records. May snooze and retry");
                    // Thread.sleep(1000); sleeping here keeps connection open. Unnecessary if the retries have been exhausted
                    sleep = true;
                  } else {
                    // String eval_status = JSONObject.fromObject(JSONObject.fromObject(tag_evals.get(0)).getJSONArray(tag).get(0))
                    // .getString("status");
                    console.logInfo("Analysis complete, processing policy evaluation result from anchore-engine");
                    String eval_status = JSONObject.fromObject(JSONObject.fromObject(tag_evals.get(0))).getString("status");
                    JSONObject gate_result = JSONObject.fromObject(JSONObject.fromObject(
                        JSONObject.fromObject(JSONObject.fromObject(tag_evals.get(0)).getJSONObject("detail")).getJSONObject("result"))
                        .getJSONObject("result"));

                    console.logDebug("anchore-engine get policy evaluation status: " + eval_status);
                    console.logDebug("anchore-engine get policy evaluation result: " + gate_result.toString());
                    for (Object key : gate_result.keySet()) {
                      try {
                        gate_results.put((String) key, gate_result.getJSONObject((String) key));
                      } catch (Exception e) {
                        console.logDebug("Ignoring error parsing policy evaluation result key: " + key);
                      }
                    }

                    // we actually got a real result
                    // this is the only way this gets flipped to true
                    if (eval_status.equals("pass")) {
                      anchore_eval_status = true;
                    }
                    done = true;
                  }
                }
              } catch (Throwable e) {
                throw e;
              }
            } catch (Throwable e) {
              throw e;
            }
          } while (!done && tryCount < maxCount);

          if (!done) {
            if (statusCode != 200) {
              console.logWarn(
                  "anchore-engine get policy evaluation failed. HTTP method: GET, URL: " + theurl + ", status: " + statusCode
                      + ", error: " + serverMessage);
            }
            console.logWarn("Exhausted all attempts polling anchore-engine. Analysis is incomplete for " + imageDigest);
            throw new AbortException(
                "Timed out waiting for anchore-engine analysis to complete (increasing engineRetries might help). Check above logs "
                    + "for errors from anchore-engine");
          } else {
            // only set to stop if an eval is successful and is reporting fail
            if (!anchore_eval_status) {
              finalAction = GATE_ACTION.FAIL;
            }
          }
        }

        try {
          try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsGatesOutputFP.write(), StandardCharsets.UTF_8))) {
            bw.write(gate_results.toString());
          }
        } catch (IOException | InterruptedException e) {
          console.logWarn("Failed to write policy evaluation output to " + jenkinsGatesOutputFP.getRemote(), e);
          throw new AbortException("Failed to write policy evaluation output to " + jenkinsGatesOutputFP.getRemote());
        }

        generateGatesSummary(jenkinsGatesOutputFP);
        return finalAction;
      } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
        throw e;
      } catch (Exception e) { // caught unknown exception, log it and wrap it
        console.logError("Failed to execute anchore-engine policy evaluation due to an unexpected error", e);
        throw new AbortException(
            "Failed to execute anchore-engine policy evaluation due to an unexpected error. Please refer to above logs for more "
                + "information");
      }
    } else {
      console.logError(
          "Image(s) were not added to anchore-engine (or a prior attempt to add images may have failed). Re-add image(s) to "
              + "anchore-engine before attempting policy evaluation ");
      throw new AbortException("Add image(s) to anchore-engine before attempting policy evaluation ");
    }

  }

  private void generateGatesSummary(FilePath jenkinsGatesOutputFP) throws AbortException {
    // Parse gate output and generate summary json
    try {
      console.logDebug("Parsing and summarizing gate output in " + jenkinsGatesOutputFP.getRemote());
      if (jenkinsGatesOutputFP.exists() && jenkinsGatesOutputFP.length() > 0) {
        JSONObject gatesJson = JSONObject.fromObject(jenkinsGatesOutputFP.readToString());
        if (gatesJson != null) {
          JSONArray summaryRows = new JSONArray();
          // Populate once and reuse
          int numColumns = 0, repoTagIndex = -1, gateNameIndex = -1, gateActionIndex = -1, whitelistedIndex = -1;

          for (Object imageKey : gatesJson.keySet()) {
            JSONObject content = gatesJson.getJSONObject((String) imageKey);
            if (null != content) {
              JSONObject result = content.getJSONObject("result");
              if (null != result) {
                // populate data from header element once, most likely for the first image
                if (numColumns <= 0 || repoTagIndex < 0 || gateNameIndex < 0 || gateActionIndex < 0 || whitelistedIndex < 0) {
                  JSONArray header = result.getJSONArray("header");
                  if (null != header) {
                    numColumns = header.size();
                    for (int i = 0; i < header.size(); i++) {
                      switch (header.getString(i)) {
                        case "Repo_Tag":
                          repoTagIndex = i;
                          break;
                        case "Gate":
                          gateNameIndex = i;
                          break;
                        case "Gate_Action":
                          gateActionIndex = i;
                          break;
                        case "Whitelisted":
                          whitelistedIndex = i;
                          break;
                        default:
                          break;
                      }
                    }
                  } else {
                    console.logWarn("\'header\' element not found in gate output, skipping summary computation for " + imageKey);
                    continue;
                  }
                } else {
                  // indices have been populated, reuse it
                }

                if (numColumns <= 0 || repoTagIndex < 0 || gateNameIndex < 0 || gateActionIndex < 0) {
                  console.logWarn("Either \'header\' element has no columns or column indices (for Repo_Tag, Gate, Gate_Action) not "
                      + "initialized, skipping summary computation for " + imageKey);
                  continue;
                }

                JSONArray rows = result.getJSONArray("rows");
                if (null != rows) {
                  int stop = 0, warn = 0, go = 0, stop_wl = 0, warn_wl = 0, go_wl = 0;
                  String repoTag = null;

                  for (int i = 0; i < rows.size(); i++) {
                    JSONArray row = rows.getJSONArray(i);
                    if (row.size() == numColumns) {
                      if (Strings.isNullOrEmpty(repoTag)) {
                        repoTag = row.getString(repoTagIndex);
                      }
                      if (!row.getString(gateNameIndex).equalsIgnoreCase("FINAL")) {
                        switch (row.getString(gateActionIndex).toLowerCase()) {
                          case "stop":
                            stop++;
                            stop_wl = (whitelistedIndex != -1 && !(row.getString(whitelistedIndex).equalsIgnoreCase("none") || row
                                .getString(whitelistedIndex).equalsIgnoreCase("false"))) ? ++stop_wl : stop_wl;
                            break;
                          case "warn":
                            warn++;
                            warn_wl = (whitelistedIndex != -1 && !(row.getString(whitelistedIndex).equalsIgnoreCase("none") || row
                                .getString(whitelistedIndex).equalsIgnoreCase("false"))) ? ++warn_wl : warn_wl;
                            break;
                          case "go":
                            go++;
                            go_wl = (whitelistedIndex != -1 && !(row.getString(whitelistedIndex).equalsIgnoreCase("none") || row
                                .getString(whitelistedIndex).equalsIgnoreCase("false"))) ? ++go_wl : go_wl;
                            break;
                          default:
                            break;
                        }
                      }
                    } else {
                      console.logWarn("Expected " + numColumns + " elements but got " + row.size() + ", skipping row " + row
                          + " in summary computation for " + imageKey);
                    }
                  }

                  if (!Strings.isNullOrEmpty(repoTag)) {
                    console.logInfo("Policy evaluation summary for " + repoTag + " - stop: " + (stop - stop_wl) + " (+" + stop_wl
                        + " whitelisted), warn: " + (warn - warn_wl) + " (+" + warn_wl + " whitelisted), go: " + (go - go_wl) + " (+"
                        + go_wl + " whitelisted), final: " + result.getString("final_action"));

                    JSONObject summaryRow = new JSONObject();
                    summaryRow.put(GATE_SUMMARY_COLUMN.Repo_Tag.toString(), repoTag);
                    summaryRow.put(GATE_SUMMARY_COLUMN.Stop_Actions.toString(), (stop - stop_wl));
                    summaryRow.put(GATE_SUMMARY_COLUMN.Warn_Actions.toString(), (warn - warn_wl));
                    summaryRow.put(GATE_SUMMARY_COLUMN.Go_Actions.toString(), (go - go_wl));
                    summaryRow.put(GATE_SUMMARY_COLUMN.Final_Action.toString(), result.getString("final_action"));
                    summaryRows.add(summaryRow);
                  } else {
                    console.logInfo("Policy evaluation summary for " + imageKey + " - stop: " + (stop - stop_wl) + " (+" + stop_wl
                        + " whitelisted), warn: " + (warn - warn_wl) + " (+" + warn_wl + " whitelisted), go: " + (go - go_wl) + " (+"
                        + go_wl + " whitelisted), final: " + result.getString("final_action"));
                    JSONObject summaryRow = new JSONObject();
                    summaryRow.put(GATE_SUMMARY_COLUMN.Repo_Tag.toString(), imageKey.toString());
                    summaryRow.put(GATE_SUMMARY_COLUMN.Stop_Actions.toString(), (stop - stop_wl));
                    summaryRow.put(GATE_SUMMARY_COLUMN.Warn_Actions.toString(), (warn - warn_wl));
                    summaryRow.put(GATE_SUMMARY_COLUMN.Go_Actions.toString(), (go - go_wl));
                    summaryRow.put(GATE_SUMMARY_COLUMN.Final_Action.toString(), result.getString("final_action"));
                    summaryRows.add(summaryRow);

                    //console.logWarn("Repo_Tag element not found in gate output, skipping summary computation for " + imageKey);
                    console.logWarn("Repo_Tag element not found in gate output, using imageId: " + imageKey);
                  }
                } else { // rows object not found
                  console.logWarn("\'rows\' element not found in gate output, skipping summary computation for " + imageKey);
                }
              } else { // result object not found, log and move on
                console.logWarn("\'result\' element not found in gate output, skipping summary computation for " + imageKey);
              }
            } else { // no content found for a given image id, log and move on
              console.logWarn("No mapped object found in gate output, skipping summary computation for " + imageKey);
            }
          }

          gateSummary = new JSONObject();
          gateSummary.put("header", generateDataTablesColumnsForGateSummary());
          gateSummary.put("rows", summaryRows);

        } else { // could not load gates output to json object
          console.logWarn("Failed to load/parse gate output from " + jenkinsGatesOutputFP.getRemote());
        }

      } else {
        console.logError("Gate output file not found or empty: " + jenkinsGatesOutputFP.getRemote());
        throw new AbortException("Gate output file not found or empty: " + jenkinsGatesOutputFP.getRemote());
      }
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) {
      console.logError("Failed to generate gate output summary", e);
      throw new AbortException("Failed to generate gate output summary");
    }
  }

  private GATE_ACTION runGatesLocal() throws AbortException {
    if (analyzed) {
      try {
        console.logInfo("Running Anchore Gates");

        FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
        FilePath jenkinsGatesOutputFP = new FilePath(jenkinsOutputDirFP, gateOutputFileName);
        String cmd = "--json gate --imagefile " + anchoreImageFileName + " --show-triggerids --show-whitelisted";

        String evalMode = config.getPolicyEvalMethod();
        if (Strings.isNullOrEmpty(evalMode)) {
          evalMode = "plainfile";
        }

        if (evalMode.equals("autosync")) {
          cmd += " --run-bundle --resultsonly";

          // try the login/bundle sync, only error out if usecachedbundle is not selected
          if (!Strings.isNullOrEmpty(config.getAnchoreioUser()) && !Strings.isNullOrEmpty(config.getAnchoreioPass())) {
            try {
              doAnchoreioLogin();
              doAnchoreioBundleSync();
            } catch (AbortException e) { // probably caught one of the thrown exceptions
              // only fail if getUseCacheBundle is unchecked
              if (!config.getUseCachedBundle()) {
                console.logWarn("Unable to log in/sync bundle");
                throw e;
              }
            }
          }

        } else if (evalMode.equals("bundlefile")) {
          cmd += " --run-bundle --resultsonly";
          if (!Strings.isNullOrEmpty(anchoreBundleFileName)) {
            cmd += " --bundlefile " + anchoreBundleFileName;
          }
        } else {
          if (!Strings.isNullOrEmpty(anchorePolicyFileName)) {
            cmd += " --policy " + anchorePolicyFileName;
          }

          if (!Strings.isNullOrEmpty(anchoreGlobalWhiteListFileName)) {
            cmd += " --global-whitelist " + anchoreGlobalWhiteListFileName;
          }
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
        } catch (IOException | InterruptedException e) {
          console.logWarn("Failed to write gates output to " + jenkinsGatesOutputFP.getRemote(), e);
          throw new AbortException("Failed to write gates output to " + jenkinsGatesOutputFP.getRemote());
        }

        generateGatesSummary(jenkinsGatesOutputFP);

        return finalAction;
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
              FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
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
      console.logDebug("Archiving results");
      //      FilePath buildWorkspaceFP = build.getWorkspace();
      //      if (null != buildWorkspaceFP) {
      ArtifactArchiver artifactArchiver = new ArtifactArchiver(jenkinsOutputDirName + "/");
      artifactArchiver.perform(build, workspace, launcher, listener);
      //      } else {
      //        console.logError("Unable to archive results due to an invalid reference to Jenkins build workspace");
      //        throw new AbortException("Unable to archive results due to an invalid reference to Jenkins build workspace");
      //      }

      // add the link in jenkins UI for anchore results
      console.logDebug("Setting up build results");

      if (finalAction != null) {
        build.addAction(new AnchoreAction(build, finalAction.toString(), jenkinsOutputDirName, gateOutputFileName, queryOutputMap,
            gateSummary.toString()));
      } else {
        build
            .addAction(new AnchoreAction(build, "", jenkinsOutputDirName, gateOutputFileName, queryOutputMap, gateSummary.toString()));
      }
      //    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      //      throw e;
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
   * Checks for minimum required config for executing step
   */
  private void checkConfig() throws AbortException {
    if (Strings.isNullOrEmpty(config.getName())) {
      console.logError("Image list file not found");
      throw new AbortException(
          "Image list file not specified. Please provide a valid image list file name in the Anchore Container Image Scanner step "
              + "and try again");
    }

    try {
      if (!new FilePath(workspace, config.getName()).exists()) {
        console.logError("Cannot find image list file \"" + config.getName() + "\" under " + workspace);
        throw new AbortException("Cannot find image list file \'" + config.getName()
            + "\'. Please ensure that image list file is created prior to Anchore Container Image Scanner step");
      }
    } catch (AbortException e) {
      throw e;
    } catch (Exception e) {
      console.logWarn("Unable to access image list file \"" + config.getName() + "\" under " + workspace, e);
      throw new AbortException("Unable to access image list file " + config.getName()
          + ". Please ensure that image list file is created prior to Anchore Container Image Scanner step");
    }

    if (config.getEnginemode().equals("anchoreengine")) {
      // no enginemode specific checks
    } else {

      if (Strings.isNullOrEmpty(config.getContainerId())) {
        console.logError("Anchore Container ID not found");
        throw new AbortException(
            "Please configure \"Anchore Container ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry. If the"
                + " container is not running, the plugin will launch it");
      }

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
      FilePath jenkinsReportDir = new FilePath(workspace, jenkinsOutputDirName);

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

    if (config.getEnginemode().equals("anchoreengine")) {
      initializeAnchoreWorkspaceEngine();
    } else {
      initializeAnchoreWorkspaceLocal();
    }
  }

  private void initializeAnchoreWorkspaceEngine() throws AbortException {
    try {
      console.logDebug("Initializing Anchore workspace (enginemode)");

      // get the input and store it in tag/dockerfile map
      FilePath inputImageFP = new FilePath(workspace, config.getName()); // Already checked in checkConfig()
      try (BufferedReader br = new BufferedReader(new InputStreamReader(inputImageFP.read(), StandardCharsets.UTF_8))) {
        String line;
        int count = 0;
        while ((line = br.readLine()) != null) {
          String imgId = null;
          String jenkinsDFile = null;
          String dfilecontents = null;
          Iterable<String> iterable = Util.IMAGE_LIST_SPLITTER.split(line);
          Iterator<String> partIterator;

          if (null != iterable && null != (partIterator = iterable.iterator()) && partIterator.hasNext()) {
            imgId = partIterator.next();

            if (partIterator.hasNext()) {
              jenkinsDFile = partIterator.next();

              StringBuilder b = new StringBuilder();
              FilePath myfp = new FilePath(workspace, jenkinsDFile);
              try (BufferedReader mybr = new BufferedReader(new InputStreamReader(myfp.read(), StandardCharsets.UTF_8))) {
                String myline;
                while ((myline = mybr.readLine()) != null) {
                  b.append(myline + '\n');
                }
              }
              console.logDebug("Dockerfile contents: " + b.toString());
              byte[] encodedBytes = Base64.encodeBase64(b.toString().getBytes(StandardCharsets.UTF_8));
              dfilecontents = new String(encodedBytes, StandardCharsets.UTF_8);

            }
          }
          if (null != imgId) {
            console.logDebug("Image tag/digest: " + imgId);
            console.logDebug("Base64 encoded Dockerfile contents: " + dfilecontents);
            input_image_dfile.put(imgId, dfilecontents);
          }
        }
      }
    } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
      throw e;
    } catch (Exception e) { // caught unknown exception, console.log it and wrap it
      console.logError("Failed to initialize Anchore workspace due to an unexpected error", e);
      throw new AbortException(
          "Failed to initialize Anchore workspace due to an unexpected error. Please refer to above logs for more information");
    }
  }


  private void initializeAnchoreWorkspaceLocal() throws AbortException {
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

      FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
      FilePath jenkinsStagedImageFP = new FilePath(jenkinsOutputDirFP, "staged_images." + buildId);
      FilePath inputImageFP = new FilePath(workspace, config.getName()); // Already checked in checkConfig()

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
        if (!Strings.isNullOrEmpty(config.getUserScripts()) && (jenkinsScriptsDir = new FilePath(workspace, config.getUserScripts()))
            .exists()) {
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
        FilePath jenkinsBundleFile;
        if (!Strings.isNullOrEmpty(config.getBundleFileOverride()) && (jenkinsBundleFile = new FilePath(workspace,
            config.getBundleFileOverride())).exists()) {
          anchoreBundleFileName = anchoreWorkspaceDirName + "/bundle.json";
          console.logDebug("Copying bundle file from Jenkins workspace: " + jenkinsBundleFile.getRemote() + ", to Anchore workspace: "
              + anchoreBundleFileName);

          rc = executeCommand(
              "docker cp " + jenkinsBundleFile.getRemote() + " " + config.getContainerId() + ":" + anchoreBundleFileName);
          if (rc != 0) {
            // TODO check with Dan if we should abort here
            console.logWarn(
                "Failed to copy bundle file from Jenkins workspace: " + jenkinsBundleFile.getRemote() + ", to Anchore workspace: "
                    + anchoreBundleFileName + ". Using default Anchore policy");
            anchoreBundleFileName = null; // reset it so it doesn't get used later
            // throw new AbortException(
            //    "Failed to copy policy file from Jenkins workspace: " + jenkinsPolicyFile.getRemote() + ", to Anchore workspace: "
            //        + anchorePolicyFileName);
          }
        } else {
          console.logInfo("Bundle file either not specified or does not exist, using default Anchore policy");
        }
      } catch (IOException | InterruptedException e) {
        console.logWarn("Failed to resolve user bundle, using default Anchore policy");
      }

      // Copy the policy file from Jenkins workspace to Anchore container
      try {
        FilePath jenkinsPolicyFile;
        if (!Strings.isNullOrEmpty(config.getPolicyName()) && (jenkinsPolicyFile = new FilePath(workspace, config.getPolicyName()))
            .exists()) {
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

      // Copy the global whitelist file from Jenkins workspace to Anchore container
      try {
        FilePath jenkinsGlobalWhitelistFile;
        if (!Strings.isNullOrEmpty(config.getGlobalWhiteList()) && (jenkinsGlobalWhitelistFile = new FilePath(workspace,
            config.getGlobalWhiteList())).exists()) {
          anchoreGlobalWhiteListFileName = anchoreWorkspaceDirName + "/globalwhitelist";
          console.logDebug("Copying global whitelist file from Jenkins workspace: " + jenkinsGlobalWhitelistFile.getRemote()
              + ", to Anchore workspace: " + anchoreGlobalWhiteListFileName);

          rc = executeCommand("docker cp " + jenkinsGlobalWhitelistFile.getRemote() + " " + config.getContainerId() + ":"
              + anchoreGlobalWhiteListFileName);
          if (rc != 0) {
            // TODO check with Dan if we should abort here
            console.logWarn("Failed to global whitelist file from Jenkins workspace: " + jenkinsGlobalWhitelistFile.getRemote()
                + ", to Anchore workspace: " + anchoreGlobalWhiteListFileName + ". Using default Anchore global whitelist");
            anchoreGlobalWhiteListFileName = null; // reset it so it doesn't get used later
          }
        } else {
          console.logInfo("Global whitelist file either not specified or does not exist, using default Anchore global whitelist");
        }
      } catch (IOException | InterruptedException e) {
        console.logWarn("Failed to resolve global whitelist, using default Anchore global whitelist");
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
          "Please configure \"Anchore Container Image ID\" under Manage Jenkins->Configure System->Anchore Configuration and retry");
    }
  }

  private JSONArray generateDataTablesColumnsForGateSummary() {
    JSONArray headers = new JSONArray();
    for (GATE_SUMMARY_COLUMN column : GATE_SUMMARY_COLUMN.values()) {
      JSONObject header = new JSONObject();
      header.put("data", column.toString());
      header.put("title", column.toString().replaceAll("_", " "));
      headers.add(header);
    }
    return headers;
  }

  private int executeAnchoreCommand(String cmd, String... envOverrides) throws AbortException {
    return executeAnchoreCommand(cmd, config.getDebug() ? console.getLogger() : null, console.getLogger(), envOverrides);
  }

  private int executeAnchoreCommand(String cmd, OutputStream out, String... envOverrides) throws AbortException {
    return executeAnchoreCommand(cmd, out, console.getLogger(), envOverrides);
  }

  /**
   * Helper for executing Anchore CLI. Abstracts docker and debug options out for the caller
   */
  private int executeAnchoreCommand(String cmd, OutputStream out, OutputStream error, String... envOverrides) throws AbortException {
    String dockerCmd = "docker exec " + config.getContainerId() + " " + ANCHORE_BINARY;

    if (config.getDebug()) {
      dockerCmd += " --debug";
    }

    if (!Strings.isNullOrEmpty(anchoreScriptsDirName)) {
      dockerCmd += " --config-override user_scripts_dir=" + anchoreScriptsDirName;
    }

    dockerCmd += " " + cmd;

    return executeCommand(dockerCmd, out, error, envOverrides);
  }

  private int executeCommand(String cmd, String... envOverrides) throws AbortException {
    // log stdout to console only if debug is turned on
    // always log stderr to console
    return executeCommand(cmd, config.getDebug() ? console.getLogger() : null, console.getLogger(), envOverrides);
  }

  private int executeCommand(String cmd, OutputStream out, OutputStream error, String... envOverrides) throws AbortException {
    int rc;

    if (config.getUseSudo()) {
      cmd = "sudo " + cmd;
    }

    Launcher.ProcStarter ps = launcher.launch();

    ps.envs(envOverrides);
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
      //ps.quiet(true);
      rc = ps.join();
      console.logDebug("Execution of \"" + cmd + "\" returned " + rc);
      return rc;
    } catch (Exception e) {
      console.logWarn("Failed to execute \"" + cmd + "\"", e);
      throw new AbortException("Failed to execute \"" + cmd + "\"");
    }
  }

  private void cleanJenkinsWorkspaceQuietly() throws IOException, InterruptedException {
    FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
    jenkinsOutputDirFP.deleteRecursive();
  }

  private int cleanAnchoreWorkspaceQuietly() throws AbortException {
    return executeCommand("docker exec " + config.getContainerId() + " rm -rf " + anchoreWorkspaceDirName);
  }
}
