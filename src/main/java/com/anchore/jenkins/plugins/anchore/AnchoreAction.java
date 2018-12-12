package com.anchore.jenkins.plugins.anchore;

import hudson.model.Action;
import hudson.model.HealthReport;
import hudson.model.HealthReportingAction;
import hudson.model.Job;
import hudson.model.Run;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import jenkins.model.Jenkins;
import jenkins.model.RunAction2;
import jenkins.model.lazy.LazyBuildMixIn;
import jenkins.tasks.SimpleBuildStep;
import jenkins.util.NonLocalizable;
import net.sf.json.JSONObject;

/**
 * Anchore plugin results for a given build are stored and subsequently retrieved from an instance of this class. Rendering/display of
 * the results is defined in the appropriate index and summary jelly files. This Jenkins Action is associated with a build (and not the
 * project which is one level up)
 */
public class AnchoreAction implements HealthReportingAction, SimpleBuildStep.LastBuildAction, RunAction2 {

  private transient Run<?, ?> build;
  private String gateStatus;
  private String gateOutputUrl;
  private Map<String, String> queryOutputUrls;
  private String gateSummary;
  private String cveListingUrl;
  private int stopActionCount;
  private int warnActionCount;
  private int goActionCount;
  private double warnActionHealthFactor;
  private double stopActionHealthFactor;

  // For backwards compatibility
  @Deprecated
  private String gateReportUrl;
  @Deprecated
  private Map<String, String> queries;


  public AnchoreAction(String gateStatus, final String jenkinsOutputDirName, String gateReport,
      Map<String, String> queryReports, String gateSummary, String cveListingFileName,
      int stopActionCount, int warnActionCount, int goActionCount, double warnActionHealthFactor, double stopActionHealthFactor) {
    this.gateStatus = gateStatus;
    this.stopActionCount = stopActionCount;
    this.warnActionCount = warnActionCount;
    this.goActionCount = goActionCount;
    this.warnActionHealthFactor = warnActionHealthFactor;
    this.stopActionHealthFactor = stopActionHealthFactor;
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
    if (null != cveListingFileName && cveListingFileName.trim().length() > 0) {
      this.cveListingUrl = "../artifact/" + jenkinsOutputDirName + "/" + cveListingFileName;
    }
  }
  
  @Override
  public void onAttached(Run<?, ?> r){
    this.build = r;
  }

  @Override
  public void onLoad(Run<?, ?> r){
    this.build = r;
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
    // queryOutputUrls was a guava TransformedEntriesMap object in plugin version < 1.0.13 and is loaded as such. Plugin versions >=
    // 1.0.13 changed the type definition and lose the transformer function required for reading the  map contents. This results in
    // a failure to load the member. Transfer the contents from the underlying guava map to a native java map using the keys and
    // some hacky guess work

    /* Find bugs does not like the instanceof check, falling back to try-catch approach
    if (!(this.queryOutputUrls instanceof HashMap)) {
      String base_path = this.gateOutputUrl.substring(0, this.gateOutputUrl.lastIndexOf('/'));
      int query_num = 0;
      Map<String, String> fixedQueryOutputUrls = new HashMap<>();
      for (String key : this.queryOutputUrls.keySet()) {
        fixedQueryOutputUrls.put(key, base_path + "/anchore_query_" + String.valueOf(++query_num) + ".json");
      }
      return fixedQueryOutputUrls;
    }*/

    Map<String, String> fixedQueryOutputUrls = new HashMap<>();
    try {
      // Fetch values in the map to verify the underlying map is functional
      if (null != this.queryOutputUrls) {
        fixedQueryOutputUrls.putAll(this.queryOutputUrls);
      }
    } catch (Exception e) {
      String base_path = this.gateOutputUrl.substring(0, this.gateOutputUrl.lastIndexOf('/'));
      int query_num = 0;
      for (String key : this.queryOutputUrls.keySet()) {
        fixedQueryOutputUrls.put(key, base_path + "/anchore_query_" + String.valueOf(++query_num) + ".json");
      }
    }
    return fixedQueryOutputUrls;
  }

  public JSONObject getGateSummary() {
    // gateSummary was a JSON object in plugin version <= 1.0.12. Jenkins does not handle this type change correctly post upgrade.
    // Summary data from the previous versions is lost during deserialization due to the type change and plugin versions > 1.0.12
    // won't be able to render the summary table only for builds that were executed using older versions of the plugin. This check
    // is necessary to ensure plugin doesn't exception out in the process
    if (null != this.gateSummary && this.gateSummary.trim().length() > 0) {
      return JSONObject.fromObject(this.gateSummary);
    } else {
      return null;
    }
  }

  public String getCveListingUrl() {
    return cveListingUrl;
  }

  public String getGateReportUrl() {
    return this.gateReportUrl;
  }

  public Map<String, String> getQueries() {
    return this.queries;
  }
  
  public int getGoActionCount(){
    return this.goActionCount;
  }
  
  public int getStopActionCount(){
    return this.stopActionCount;
  }
  
  public int getWarnActionCount(){
    return this.warnActionCount;
  }

  @Override
  public HealthReport getBuildHealth(){
    int health = Math.min(100, Math.max(0, 100 - (int)(this.stopActionCount * this.stopActionHealthFactor 
            + this.warnActionCount * this.warnActionHealthFactor)));
    return new HealthReport(health, new NonLocalizable(String.format( // Plugin is not localized yet
            "Anchore policy evaluation resulted in %d stop and %d warn actions.", this.stopActionCount, this.warnActionCount)));
  }

  @Override
  public Collection<? extends Action> getProjectActions() {
    Job<?,?> job = this.build.getParent();
    return Collections.singleton(new AnchoreProjectAction(job));
  }

  /**
   * Gets the Anchore result of the previous build, if it's recorded, or null.
   * @return the previous AnchoreAction
   */
  public AnchoreAction getPreviousResult() {
    Run<?,?> b = this.build;
    Set<Integer> loadedBuilds;
    if (this.build.getParent() instanceof LazyBuildMixIn.LazyLoadingJob) {
      loadedBuilds = ((LazyBuildMixIn.LazyLoadingJob<?,?>) this.build.getParent()).getLazyBuildMixIn()._getRuns().getLoadedBuilds().keySet();
    } else {
      loadedBuilds = null;
    }
    while(true) {
      b = loadedBuilds == null || loadedBuilds.contains(b.number - /* assuming there are no gaps */1) ? b.getPreviousBuild() : null;
      if (b == null) {
        return null;
      }
      AnchoreAction r = b.getAction(AnchoreAction.class);
      if (r != null) {
        if (r == this) {
          throw new IllegalStateException(this + " was attached to both " + b + " and " + this.build);
        }
        if (r.build.number != b.number) {
          throw new IllegalStateException(r + " was attached to both " + b + " and " + r.build);
        }
        return r;
      }
    }
  }
}
