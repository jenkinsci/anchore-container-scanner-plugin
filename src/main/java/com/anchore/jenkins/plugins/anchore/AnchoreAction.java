package com.anchore.jenkins.plugins.anchore;

import com.google.common.base.Function;
//import com.google.common.collect.Maps;
import hudson.model.Action;
import hudson.model.Run;
import java.util.Map;
import java.util.HashMap;
import javax.annotation.Nullable;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

/**
 * Anchore plugin results for a given build are stored and subsequently retrieved from an instance of this class. Rendering/display of
 * the results is defined in the appropriate index and summary jelly files. This Jenkins Action is associated with a build (and not the
 * project which is one level up)
 */
public class AnchoreAction implements Action {

  private Run<?, ?> build;
  private String gateStatus;
  private String gateOutputUrl;
  private Map<String, String> queryOutputUrls;
  private String gateSummary;

  // For backwards compatibility
  @Deprecated
  private String gateReportUrl;
  @Deprecated
  private Map<String, String> queries;


  public AnchoreAction(Run<?, ?> build, String gateStatus, final String jenkinsOutputDirName, String gateReport,
      Map<String, String> queryReports, String gateSummary) {
    this.build = build;
    this.gateStatus = gateStatus;
    this.gateOutputUrl = "../artifact/" + jenkinsOutputDirName + "/" + gateReport;

    this.queryOutputUrls = new HashMap<String, String>();
    for (Map.Entry<String, String> entry : queryReports.entrySet()) {
	String k = entry.getKey();
	String v = entry.getValue();
	String newv = "../artifact/" + jenkinsOutputDirName + "/" + v;
	this.queryOutputUrls.put(k, newv);
    }

    // original maps conversion method
    /*
    this.queryOutputUrls = Maps.transformValues(queryReports, new Function<String, String>() {

      @Override
      public String apply(@Nullable String queryOutput) {
        return "../artifact/" + jenkinsOutputDirName + "/" + queryOutput;
      }
    });
    */
    this.gateSummary = gateSummary;
  }

  @Override
  public String getIconFileName() {
    return Jenkins.RESOURCE_PATH + "/plugin/anchore-container-scanner/images/anchore.png";
  }

  @Override
  public String getDisplayName() {
    return "Anchore Report (" + gateStatus + ")";
  }

  @Override
  public String getUrlName() {
    return "anchore-results";
  }

  public Run<?, ?> getBuild() {
    return this.build;
  }

  public String getGateStatus() {
    return gateStatus;
  }

  public String getGateOutputUrl() {
    return this.gateOutputUrl;
  }

  public Map<String, String> getQueryOutputUrls() {
    return this.queryOutputUrls;
  }

  public JSONObject getGateSummary() {
      JSONObject ret = JSONObject.fromObject(gateSummary);
      return ret;
  }

  public String getGateReportUrl() {
    return this.gateReportUrl;
  }

  public Map<String, String> getQueries() {
    return this.queries;
  }
}

