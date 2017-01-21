package com.anchore.jenkins.plugins.anchore;

import hudson.model.AbstractBuild;
import hudson.model.Action;
import java.util.Map;
import java.util.TreeMap;

public class AnchoreAction implements Action {

  private String gateStatus;
  private String gateReportUrl;
  private String queryReportUrl;
  private Map<String, String> queries;
  private AbstractBuild<?, ?> build;

  public AnchoreAction(AbstractBuild<?, ?> build, String gateStatus, String euid, Map<String, String> queries) {
    this.gateReportUrl = "../artifact/AnchoreReport." + euid + "/anchore_gates_format.html";
    this.queryReportUrl = "../artifact/AnchoreReport." + euid + "/anchore_query_format.html";
    this.build = build;
    this.gateStatus = gateStatus;
    this.queries = new TreeMap<String, String>();
    for (Map.Entry<String, String> entry : queries.entrySet()) {
      this.queries.put("../artifact/AnchoreReport." + euid + "/" + entry.getKey() + "_format.html", entry.getValue());
    }
  }

  @Override
  public String getIconFileName() {
    return "/plugin/anchore-container-scanner/images/anchore.png";
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

  public String getGateReportUrl() {
    return this.gateReportUrl;
  }

  public String getQueryReportUrl() {
    return this.queryReportUrl;
  }

  public Map<String, String> getQueries() {
    return (this.queries);
  }
}

