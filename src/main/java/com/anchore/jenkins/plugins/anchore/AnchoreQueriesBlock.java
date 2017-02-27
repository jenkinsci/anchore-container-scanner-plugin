package com.anchore.jenkins.plugins.anchore;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Wrapper for Jenkins config slurped in using foldable section construct. An instance of this class is used for transporting elements
 * defined within the optionalBlock jelly tag
 */
public class AnchoreQueriesBlock implements Serializable {

  private static final long serialVersionUID = 1L;

  private List<AnchoreQuery> inputQueries;

  public List<AnchoreQuery> getInputQueries() {
    return inputQueries;
  }

  @DataBoundConstructor
  public AnchoreQueriesBlock(List<AnchoreQuery> inputQueries) {
    this.inputQueries = inputQueries != null ? new ArrayList<>(inputQueries) : Collections.<AnchoreQuery>emptyList();
  }
}

