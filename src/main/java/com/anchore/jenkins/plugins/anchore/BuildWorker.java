package com.anchore.jenkins.plugins.anchore;

import com.anchore.jenkins.plugins.anchore.Util.GATE_ACTION;
import com.anchore.jenkins.plugins.anchore.Util.GATE_SUMMARY_COLUMN;
import com.google.common.base.Strings;
import com.google.common.base.Joiner;
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
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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
  private static final String GATES_OUTPUT_PREFIX = "anchore_gates";
  private static final String CVE_LISTING_PREFIX = "anchore_security";
  private static final String JENKINS_DIR_NAME_PREFIX = "AnchoreReport.";
  private static final String JSON_FILE_EXTENSION = ".json";
  private static final String AE_VULNS_PREFIX = "anchoreengine-api-response-vulnerabilities-";
  private static final String AE_EVAL_PREFIX = "anchoreengine-api-response-evaluation-";

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
  private Map<String, String> input_image_dfile = new LinkedHashMap<>();
  private Map<String, String> input_image_imageDigest = new LinkedHashMap<>();
  private String gateOutputFileName;
  private GATE_ACTION finalAction;
  private JSONObject gateSummary;
  private int totalStopActionCount = 0;
  private int totalWarnActionCount = 0;
  private int totalGoActionCount = 0;
  private String cveListingFileName;

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
      } catch (Exception innere) {

      } finally {
        throw new AbortException("Failed to initialize worker for plugin execution, check logs for corrective action");
      }
    }
  }

  public void runAnalyzer() throws AbortException {
    runAnalyzerEngine();
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
        List<String> queryList = new ArrayList<>();
        String queryStr = null;

        console.logInfo("Submitting " + tag + " for analysis");

        try (CloseableHttpClient httpclient = makeHttpClient(sslverify)) {
          // Prep POST request
          String theurl = config.getEngineurl().replaceAll("/+$", "") + "/images";

          // Disable autosubscribe if necessary
          if (!config.getAutoSubscribeTagUpdates()){
            queryList.add("autosubscribe=false");
          }

          // Enable force if necessary
          if (config.getForceAnalyze()) {
            queryList.add("force=true");
          }

          if (!queryList.isEmpty()){
            queryStr = Joiner.on('&').skipNulls().join(queryList);
          }

          if (!Strings.isNullOrEmpty(queryStr)) {
            theurl += "?" + queryStr;
          }

          // Prep request body
          JSONObject jsonBody = new JSONObject();
          jsonBody.put("tag", tag);
          if (null != dfile) {
            jsonBody.put("dockerfile", dfile);
          }
          if (null != config.getAnnotations() && !config.getAnnotations().isEmpty()) {
            JSONObject annotations = new JSONObject();
            for (Annotation a : config.getAnnotations()) {
              annotations.put(a.getKey(), a.getValue());
            }
            jsonBody.put("annotations", annotations);
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
              console.logInfo("Analysis request accepted, received image digest " + imageDigest);
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

  public GATE_ACTION runGates() throws AbortException {
    return runGatesEngine();
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
    int counter = 0;

    finalAction = GATE_ACTION.PASS;
    if (analyzed) {
      try {
        JSONObject gate_results = new JSONObject();

        for (Map.Entry<String, String> entry : input_image_imageDigest.entrySet()) {
          String tag = entry.getKey();
          String imageDigest = entry.getValue();

          console.logInfo("Waiting for analysis of " + tag + ", polling status periodically");

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
                    // Write api response to a file as it is
                    String jenkinsAEResponseFileName = AE_EVAL_PREFIX + (++counter) + JSON_FILE_EXTENSION;
                    FilePath jenkinsAEResponseFP = new FilePath(jenkinsOutputDirFP, jenkinsAEResponseFileName);
                    try {
                      console.logDebug("Writing anchore-engine policy evaluation response to " + jenkinsAEResponseFP.getRemote());
                      try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsAEResponseFP.write(), StandardCharsets.UTF_8))) {
                        bw.write(responseBody);
                      }
                    } catch (IOException | InterruptedException e) {
                      console.logWarn("Failed to write anchore-engine policy evaluation response to " + jenkinsAEResponseFP.getRemote(), e);
                      throw new AbortException("Failed to write anchore-engine policy evaluation response to " + jenkinsAEResponseFP.getRemote());
                    }

                    // String eval_status = JSONObject.fromObject(JSONObject.fromObject(tag_evals.get(0)).getJSONArray(tag).get(0))
                    // .getString("status");
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
                    console.logInfo("Completed analysis and processed policy evaluation result");
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
          console.logDebug("Writing policy evaluation result to " + jenkinsGatesOutputFP.getRemote());
          try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsGatesOutputFP.write(), StandardCharsets.UTF_8))) {
            bw.write(gate_results.toString());
          }
        } catch (IOException | InterruptedException e) {
          console.logWarn("Failed to write policy evaluation output to " + jenkinsGatesOutputFP.getRemote(), e);
          throw new AbortException("Failed to write policy evaluation output to " + jenkinsGatesOutputFP.getRemote());
        }

        generateGatesSummary(gate_results);
        console.logInfo("Anchore Container Image Scanner Plugin step result - " + finalAction);
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
          "Image(s) were not added to anchore-engine (or a prior attempt to add images may have failed). Re-submit image(s) to "
              + "anchore-engine before attempting policy evaluation");
      throw new AbortException("Submit image(s) to anchore-engine for analysis before attempting policy evaluation");
    }

  }

  private void runVulnerabilityListing() throws AbortException {
    if (analyzed) {
      String username = config.getEngineuser();
      String password = config.getEnginepass();
      boolean sslverify = config.getEngineverify();

      FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
      int counter = 0;

      CredentialsProvider credsProvider = new BasicCredentialsProvider();
      credsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
      HttpClientContext context = HttpClientContext.create();
      context.setCredentialsProvider(credsProvider);

      try {
        JSONObject securityJson = new JSONObject();
        JSONArray columnsJson = new JSONArray();
        for (String column : Arrays.asList("Tag", "CVE ID", "Severity", "Vulnerability Package", "Fix Available", "URL")) {
          JSONObject columnJson = new JSONObject();
          columnJson.put("title", column);
          columnsJson.add(columnJson);
        }
        JSONArray dataJson = new JSONArray();

        for (Map.Entry<String, String> entry : input_image_imageDigest.entrySet()) {
          String input = entry.getKey();
          String digest = entry.getValue();

          try (CloseableHttpClient httpclient = makeHttpClient(sslverify)) {
            console.logInfo("Querying vulnerability listing for " + input);
            String theurl = config.getEngineurl().replaceAll("/+$", "") + "/images/" + digest + "/vuln/all";
            HttpGet httpget = new HttpGet(theurl);
            httpget.addHeader("Content-Type", "application/json");

            console.logDebug("anchore-engine get vulnerability listing URL: " + theurl);
            try (CloseableHttpResponse response = httpclient.execute(httpget, context)) {
              int statusCode = response.getStatusLine().getStatusCode();
              if (statusCode != 200) {
                String serverMessage = EntityUtils.toString(response.getEntity());
                console.logWarn(
                    "anchore-engine get vulnerability listing failed. URL: " + theurl + ", status: " + response.getStatusLine()
                        + ", error: " + serverMessage);
                throw new AbortException("Failed to fetch vulnerability listing from anchore-engine");
              } else {
                String responseBody = EntityUtils.toString(response.getEntity());
                // Write api response to a file as it is
                String jenkinsAEResponseFileName = AE_VULNS_PREFIX + (++counter) + JSON_FILE_EXTENSION;
                FilePath jenkinsAEResponseFP = new FilePath(jenkinsOutputDirFP, jenkinsAEResponseFileName);
                try {
                  console.logDebug("Writing anchore-engine vulnerabilities listing response to " + jenkinsAEResponseFP.getRemote());
                  try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsAEResponseFP.write(), StandardCharsets.UTF_8))) {
                    bw.write(responseBody);
                  }
                } catch (IOException | InterruptedException e) {
                  console.logWarn("Failed to write anchore-engine vulnerabilities listing response to " + jenkinsAEResponseFP.getRemote(), e);
                  throw new AbortException("Failed to write anchore-engine vulnerabilities listing response to " + jenkinsAEResponseFP.getRemote());
                }

                JSONObject responseJson = JSONObject.fromObject(responseBody);
                JSONArray vulList = responseJson.getJSONArray("vulnerabilities");
                for (int i = 0; i < vulList.size(); i++) {
                  JSONObject vulnJson = vulList.getJSONObject(i);
                  JSONArray vulnArray = new JSONArray();
                  vulnArray.addAll(Arrays
                      .asList(input, vulnJson.getString("vuln"), vulnJson.getString("severity"), vulnJson.getString("package"),
                          vulnJson.getString("fix"),
                          "<a href='" + vulnJson.getString("url") + "'>" + vulnJson.getString("url") + "</a>"));
                  dataJson.add(vulnArray);
                }
              }
            } catch (Throwable t) {
              throw t;
            }
          } catch (Throwable t) {
            throw t;
          }
        }
        securityJson.put("columns", columnsJson);
        securityJson.put("data", dataJson);

        cveListingFileName = CVE_LISTING_PREFIX + JSON_FILE_EXTENSION;
        FilePath jenkinsQueryOutputFP = new FilePath(jenkinsOutputDirFP, cveListingFileName);
        try {
          console.logDebug("Writing vulnerability listing result to " + jenkinsQueryOutputFP.getRemote());
          try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(jenkinsQueryOutputFP.write(), StandardCharsets.UTF_8))) {
            bw.write(securityJson.toString());
          }
        } catch (IOException | InterruptedException e) {
          console.logWarn("Failed to write vulnerability listing to " + jenkinsQueryOutputFP.getRemote(), e);
          throw new AbortException("Failed to write vulnerability listing to " + jenkinsQueryOutputFP.getRemote());
        }
      } catch (AbortException e) { // probably caught one of the thrown exceptions, let it pass through
        throw e;
      } catch (Exception e) { // caught unknown exception, log it and wrap it
        console.logError("Failed to fetch vulnerability listing from anchore-engine due to an unexpected error", e);
        throw new AbortException(
            "Failed to fetch vulnerability listing from anchore-engine due to an unexpected error. Please refer to above logs for "
                + "more information");
      }
    } else {
      console.logError(
          "Image(s) were not added to anchore-engine (or a prior attempt to add images may have failed). Re-submit image(s) to "
              + "anchore-engine before attempting vulnerability listing");
      throw new AbortException("Submit image(s) to anchore-engine for analysis before attempting vulnerability listing");
    }
  }

  private void generateGatesSummary(JSONObject gatesJson) {
    console.logDebug("Summarizing policy evaluation results");
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

              totalStopActionCount += (stop - stop_wl);
              totalWarnActionCount += (warn - warn_wl);
              totalGoActionCount += (go - go_wl);
              
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
      console.logWarn("Invalid input to generate gates summary");
    }
  }

  public void runQueries() throws AbortException {
    runVulnerabilityListing();
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
            gateSummary.toString(), cveListingFileName, totalStopActionCount, totalWarnActionCount, totalGoActionCount));
      } else {
        build.addAction(new AnchoreAction(build, "", jenkinsOutputDirName, gateOutputFileName, queryOutputMap, gateSummary.toString(),
            cveListingFileName, totalStopActionCount, totalWarnActionCount, totalGoActionCount));
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
  }

  private void initializeJenkinsWorkspace() throws AbortException {
    try {
      console.logDebug("Initializing Jenkins workspace");

      if (Strings.isNullOrEmpty(buildId = build.getParent().getDisplayName() + "_" + build.getNumber())) {
        console.logWarn("Unable to generate a unique identifier for this build due to invalid configuration");
        throw new AbortException("Unable to generate a unique identifier for this build due to invalid configuration");
      }

      // ArtifactArchiver.perform() cannot parse file paths with commas, which buildId will have in some cases, for
      // example if this is a matrix job. So replace any commas in it with underscores to separate the matrix values.
      jenkinsOutputDirName = JENKINS_DIR_NAME_PREFIX + buildId.replaceAll(",", "_");
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
    initializeAnchoreWorkspaceEngine();
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

  private void cleanJenkinsWorkspaceQuietly() throws IOException, InterruptedException {
    FilePath jenkinsOutputDirFP = new FilePath(workspace, jenkinsOutputDirName);
    jenkinsOutputDirFP.deleteRecursive();
  }
}
