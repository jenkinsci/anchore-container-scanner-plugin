package com.anchore.jenkins.plugins.anchore;

import hudson.Functions;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import hudson.util.Area;
import hudson.util.ColorPalette;
import hudson.util.DataSetBuilder;
import hudson.util.Graph;
import hudson.util.ShiftedCategoryAxis;
import hudson.util.StackedAreaRenderer2;
import hudson.util.ChartUtil.NumberOnlyBuildLabel;
import jenkins.model.Jenkins;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.StackedAreaRenderer;
import org.jfree.data.category.CategoryDataset;
import org.jfree.ui.RectangleInsets;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.servlet.http.HttpServletResponse;

import java.awt.Color;
import java.io.IOException;

/**
 * Project action object which displays the trend report on the project top page.
 */
public class AnchoreProjectAction implements Action {
  private final static class AnchoreTrendGraph extends Graph {
    private static final int MAX_HISTORY_DEFAULT = 100;
    private AnchoreAction base;
    private String relPath;

    private static Area calcDefaultSize() {
      Area res = Functions.getScreenResolution();
      if(res!=null && res.width<=800)
        return new Area(250,100);
      else
        return new Area(500,200);
    }
    
    /**
     * Initialize the trend graph from a base AnchoreAction using a calculated default size.
     *
     * @param base the most recent AnchoreAction up to which the trend is shown
     * @param relPath URL rel path for tooltip URLs
     */
    protected AnchoreTrendGraph(AnchoreAction base, String relPath){
      this(base, calcDefaultSize(), relPath);
    }

    /**
     * Initialize the trend graph from a base AnchoreAction using a given default size.
     *
     * @param base the most recent AnchoreAction up to which the trend is shown
     * @param defaultSize graph's default size
     * @param relPath URL rel path for tooltip URLs
     */
    private AnchoreTrendGraph(AnchoreAction base, Area defaultSize, String relPath){
      super(base.getBuild().getTimestamp(), defaultSize.width, defaultSize.height);
      this.base = base;
      this.relPath = relPath;
    }

    private CategoryDataset buildDataSet() {
      DataSetBuilder<String, NumberOnlyBuildLabel> dsb = new DataSetBuilder<>();

      int cap = Integer.getInteger(AnchoreAction.class.getName() + ".anchore.trend.max", AnchoreTrendGraph.MAX_HISTORY_DEFAULT);
      int count = 0;
      for (AnchoreAction a = this.base; a != null; a = a.getPreviousResult()) {
        if (++count > cap) {
          break;
        }
        dsb.add(a.getGoActionCount(), "0_go", new NumberOnlyBuildLabel(a.getBuild()));
        dsb.add(a.getWarnActionCount(), "1_warn", new NumberOnlyBuildLabel(a.getBuild()));
        dsb.add(a.getStopActionCount(), "2_stop", new NumberOnlyBuildLabel(a.getBuild()));
      }
      return dsb.build();
    }
    
    @Override
    protected JFreeChart createGraph(){
      CategoryDataset dataset = buildDataSet();
      final JFreeChart chart = ChartFactory.createStackedAreaChart(
        null, // chart title
        null, // category axis label
        "count", // range axis label
        dataset,
        PlotOrientation.VERTICAL,
        false, // include legend
        true, // generate tooltips
        false // generate urls
      );

      chart.setBackgroundPaint(Color.white);

      final CategoryPlot plot = chart.getCategoryPlot();

      plot.setBackgroundPaint(Color.WHITE);
      plot.setOutlinePaint(null);
      plot.setForegroundAlpha(0.8f);
      plot.setRangeGridlinesVisible(true);
      plot.setRangeGridlinePaint(Color.BLACK);

      CategoryAxis domainAxis = new ShiftedCategoryAxis(null);
      plot.setDomainAxis(domainAxis);
      domainAxis.setCategoryLabelPositions(CategoryLabelPositions.UP_90);
      domainAxis.setLowerMargin(0.0);
      domainAxis.setUpperMargin(0.0);
      domainAxis.setCategoryMargin(0.0);

      final NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
      rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());

      StackedAreaRenderer ar = new StackedAreaRenderer2() {
        @Override
        public String generateURL(CategoryDataset data, int row, int column) {
          NumberOnlyBuildLabel label = (NumberOnlyBuildLabel) data.getColumnKey(column);
          return relPath + label.getRun().getNumber() + "/anchore-results/";
        }
    
        @Override
        public String generateToolTip(CategoryDataset data, int row, int column) {
          NumberOnlyBuildLabel label = (NumberOnlyBuildLabel) data.getColumnKey(column);
          AnchoreAction a = label.getRun().getAction(AnchoreAction.class);
          switch (row) {
            case 0:
              return label.getRun().getDisplayName() + ": " + a.getGoActionCount() + " Go Actions";
            case 1:
              return label.getRun().getDisplayName() + ": " + a.getWarnActionCount() + " Warn Actions";
            default:
              return label.getRun().getDisplayName() + ": " + a.getStopActionCount() + " Stop Actions";
          }
        }
      };
      ar.setSeriesPaint(0, ColorPalette.BLUE); // Go
      ar.setSeriesPaint(1, ColorPalette.YELLOW); // Warn
      ar.setSeriesPaint(2, ColorPalette.RED); // Stop
      plot.setRenderer(ar);

      plot.setInsets(new RectangleInsets(0, 0, 0, 5.0));

      return chart;
    }
  }
  
  /**
   * Parent that owns this action.
   */
  public final Job<?,?> job;

  /**
   * Create new AnchoreProjectAction instance.
   *
   * @param job
   */
  public AnchoreProjectAction(Job<?,?> job) {
    this.job = job;
  }

  @Override
  public String getIconFileName() {
    return Jenkins.RESOURCE_PATH + "/plugin/anchore-container-scanner/images/anchore.png";
  }

  @Override
  public String getDisplayName() {
    return "Anchore Report";
  }

  @Override
  public String getUrlName() {
    return "anchore";
  }
  
  /**
   * Redirects the index page to the last report.
   *
   * @param request Stapler request
   * @param response Stapler response
   * @throws IOException in case of an error
   */
  public void doIndex(final StaplerRequest request, final StaplerResponse response) throws IOException {
    Run<?, ?> lastRun = this.job.getLastCompletedBuild();
    if (lastRun != null) {
      AnchoreAction a = lastRun.getAction(AnchoreAction.class);
      if (a != null)
        response.sendRedirect2(String.format("../%d/%s", lastRun.getNumber(), a.getUrlName()));
    }
  }

  /**
   * @return the most current AnchoreAction of the associated job
   */
  public AnchoreAction getLastAnchoreAction() {
    final Run<?,?> tb = this.job.getLastSuccessfulBuild();

    Run<?,?> b = this.job.getLastBuild();
    while (b != null) {
      AnchoreAction a = b.getAction(AnchoreAction.class);
      if (a != null && (!b.isBuilding())) {
        return a;
      }
      if (b == tb) {
        // no Anchore result available
        return null;
      }
      b = b.getPreviousBuild();
    }
    return null;
  }
  
  private String getRelPath(StaplerRequest req) {
      String relPath = req.getParameter("rel");
      if (relPath == null) {
        return "";
      }
      return relPath;
  }
  
  /**
   * Generates the Anchore trend graph
   * @return graph object
   */
  public Graph getTrendGraph() {
    final AnchoreAction a = getLastAnchoreAction();
    if (a != null) {
      return new AnchoreTrendGraph(a, getRelPath(Stapler.getCurrentRequest()));
    }else{
      Stapler.getCurrentResponse().setStatus(HttpServletResponse.SC_NOT_FOUND);
      return null;
    }
  }
}
