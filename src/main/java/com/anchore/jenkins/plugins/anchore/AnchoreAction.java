package com.anchore.jenkins.plugins.anchore;

import com.google.common.base.Function;
import com.google.common.collect.Maps;
import hudson.model.AbstractBuild;
import hudson.model.Action;
import java.util.Map;
import javax.annotation.Nullable;
import jenkins.model.Jenkins;

public class AnchoreAction implements Action {

  private AbstractBuild<?, ?> build;
  private String gateStatus;
  private String gateOutputUrl;
  private Map<String, String> queryOutputUrls;

  // For backwards compatibility
  @Deprecated
  private String gateReportUrl;
  @Deprecated
  private Map<String, String> queries;


  public AnchoreAction(AbstractBuild<?, ?> build, String gateStatus, final String jenkinsOutputDirName, String gateReport,
      Map<String, String> queryReports) {
    this.build = build;
    this.gateStatus = gateStatus;
    this.gateOutputUrl = "../artifact/" + jenkinsOutputDirName + "/" + gateReport;
    this.queryOutputUrls = Maps.transformValues(queryReports, new Function<String, String>() {

      @Override
      public String apply(@Nullable String queryOutput) {
        return "../artifact/" + jenkinsOutputDirName + "/" + queryOutput;
      }
    });
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

  public AbstractBuild<?, ?> getBuild() {
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

  public String getGateReportUrl() {
    return this.gateReportUrl;
  }

  public Map<String, String> getQueries() {
    return this.queries;
  }
}

