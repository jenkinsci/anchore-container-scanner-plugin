package com.anchore.jenkins.plugins.anchore;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * TODO Some description here
 */
public class AnchoreQuery extends AbstractDescribableImpl<AnchoreQuery> {

  private String query;

  public String getQuery() {
    return query;
  }

  @DataBoundConstructor
  public AnchoreQuery(String query) {
    this.query = query;
  }

  @Extension
  public static class DescriptorImpl extends Descriptor<AnchoreQuery> {

    @Override
    public String getDisplayName() {
      return "Anchore Query";
    }
  }
}
