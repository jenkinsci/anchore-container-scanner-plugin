package com.anchore.jenkins.plugins.anchore;
import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.model.AbstractBuild;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.model.BuildListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.AbortException;
import hudson.tasks.ArtifactArchiver;

import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;

import hudson.EnvVars;
import hudson.util.ArgumentListBuilder;
import java.io.File;
import java.io.PrintStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.Map;

import java.nio.file.*;
import static java.nio.file.FileVisitResult.*;
import java.nio.file.attribute.*;

public class AnchoreBuilder extends Builder {
    private String name;
    private String policyName;
    private String workspace;
    private String anchoreWorkspace;
    private String buildId;
    private String euid;
    private String targetImageFile;
    private String targetPolicyFile;
    private String containerId;
    private String containerImageId;
    private String localVol;
    private String query1;
    private String query2;
    private String query3;
    private String query4;

    private List<String> anchoreInputImages;
    private List<String> oFiles;
    private TreeMap<String, String> queries;

    private File gatesOutputFile;
    private File anchorePolicyFile;
    private File anchoreImageFile;
    private File anchoreLogFile;
    private PrintStream anchoreLogStream;
    private boolean debug;
    private boolean useSudo;
    private final boolean bailOnPluginFail;
    private final boolean bailOnFail;
    private final boolean bailOnWarn;
    private final boolean doAnalyze;
    private final boolean doGate;
    private final boolean doQuery;
    private final boolean doCleanup;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    //    public AnchoreBuilder(String name, String policyName, boolean bailOnFail, boolean bailOnWarn, boolean doAnalyze, boolean doGate, boolean doQuery, boolean doCleanup) {
    public AnchoreBuilder(String name, String policyName, boolean bailOnFail, boolean bailOnWarn, boolean doQuery, boolean doCleanup, boolean bailOnPluginFail, String query1, String query2, String query3, String query4) {
	this.bailOnPluginFail = bailOnPluginFail;
	this.bailOnFail = bailOnFail;
	this.bailOnWarn = bailOnWarn;
        this.name = name;
        this.policyName = policyName;
	this.doAnalyze = true;
	this.doGate = true;
	this.doQuery = doQuery;
	this.doCleanup = doCleanup;
	this.query1 = query1;
	this.query2 = query2;
	this.query3 = query3;
	this.query4 = query4;
    }

    public boolean getBailOnWarn() {
	return (bailOnWarn);
    }

    public boolean getBailOnFail() {
	return (bailOnFail);
    }

    public boolean getBailOnPluginFail() {
	return(bailOnPluginFail);
    }

    public boolean getDoAnalyze() {
	return (doAnalyze);
    }

    public boolean getDoGate() {
	return (doGate);
    }

    public boolean getDoQuery() {
	return (doQuery);
    }

    public boolean getDoCleanup() {
	return (doCleanup);
    }

    public String getName() {
        return (name);
    }

    public String getQuery1() {
        return (query1);
    }
    public String getQuery2() {
        return (query2);
    }
    public String getQuery3() {
        return (query3);
    }
    public String getQuery4() {
        return (query4);
    }

    public String getPolicyName() {
        return (policyName);
    }

    public boolean selectPluginExitStatus(BuildListener listener) {
	if (bailOnPluginFail) {
	    return(false);
	}
	listener.getLogger().println("[anchore][error] Critical error encountered, but Anchore build step is configured to proceed - ignoring error.");
	return(true);
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) throws AbortException, java.lang.InterruptedException {
	int exitCode = 0;
	PrintStream outStream;
	boolean rc;
	TreeMap<String, String> queriesOutput = new TreeMap<String, String>();

	try {

	    listener.getLogger().println("[anchore] Anchore Plugin Started:");
	    if (!getDescriptor().getEnabled()) {
		listener.getLogger().println("[anchore] Anchore plugin is disabled - please enable the plugin in the global Anchore configuration section in Jenkins and try again");
		return(true);
	    }

	    rc = anchoreSetup(build, launcher, listener);
	    if (!rc) {
		listener.getLogger().println("[anchore] failed to setup Anchore - please check the output above");
		return(selectPluginExitStatus(listener));
	    }

	    if (debug) {
		listener.getLogger().println("[anchore][config][global] enabled: " + String.valueOf(getDescriptor().getEnabled()));
		listener.getLogger().println("[anchore][config][global] debug: " + String.valueOf(getDescriptor().getDebug()));
		listener.getLogger().println("[anchore][config][global] useSudo: " + String.valueOf(getDescriptor().getUseSudo()));
		listener.getLogger().println("[anchore][config][global] containerImageId: " + getDescriptor().getContainerImageId());
		listener.getLogger().println("[anchore][config][global] containerId: " + getDescriptor().getContainerId());
		listener.getLogger().println("[anchore][config][global] localVol: " + getDescriptor().getLocalVol());

		
		listener.getLogger().println("[anchore][config][build] doAnalyze: " + String.valueOf(doAnalyze));
		listener.getLogger().println("[anchore][config][build] doGates: " + String.valueOf(doGate));
		listener.getLogger().println("[anchore][config][build] doQuery: " + String.valueOf(doQuery));
		listener.getLogger().println("[anchore][config][build] doCleanup: " + String.valueOf(doCleanup));
		listener.getLogger().println("[anchore][config][build] imageFile: " + name);
		listener.getLogger().println("[anchore][config][build] policyFile: " + policyName);
		listener.getLogger().println("[anchore][config][build] stopOnGateStop: " + String.valueOf(bailOnFail));
		listener.getLogger().println("[anchore][config][build] stopOnGateWarn: " + String.valueOf(bailOnWarn));
	    }

	    if (doAnalyze) {
		listener.getLogger().println("[anchore][info][info] Running Anchore Analyzer:");
	    
		if (this.debug) {
		    exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--debug", "analyze", "--imagefile", targetImageFile);
		} else {
		    exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "analyze", "--imagefile", targetImageFile);
		}

		
		listener.getLogger().println("[anchore][info] Done Running Anchore Analyzer: exitcode="+exitCode);
		if (exitCode != 0) {
		    listener.getLogger().println("[anchore][error] Anchore analyzer failed: check output above for details");
		    if (bailOnPluginFail) {
			return(false);
		    }
		}
	    }

	    if (doQuery) {
		for (Map.Entry<String, String> entry : queries.entrySet()) {
		    String anchoreQuery = entry.getValue();
		    if (anchoreQuery != null && !anchoreQuery.isEmpty()) {
			listener.getLogger().println("[anchore][info] " + entry.getKey() + " : " + entry.getValue());
			File queryOutputFile = new File(anchoreWorkspace, entry.getKey() + ".html");
			outStream = new PrintStream(queryOutputFile, "UTF-8");
		    
			listener.getLogger().println("[anchore][info] Running Anchore Query: " + entry.getValue());
		    
			if (this.debug) {
			    exitCode = runAnchoreCmd(launcher, outStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--debug", "--html", "query", "--imagefile", targetImageFile, entry.getValue());
			} else {
			    exitCode = runAnchoreCmd(launcher, outStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--html", "query", "--imagefile", targetImageFile, entry.getValue());
			}
			if (queryOutputFile.exists() && queryOutputFile.length() > 0) {
			    queriesOutput.put(entry.getKey(), entry.getValue());
			}
			listener.getLogger().println("[anchore][info] Done Running Anchore Query: exitcode="+exitCode);
		    }
		}
	    }

	    if (doGate) {
		outStream = new PrintStream(gatesOutputFile, "UTF-8");

		listener.getLogger().println("[anchore][info] Running Anchore Gates:");

		if (anchorePolicyFile != null && anchorePolicyFile.exists()) {
		    if (this.debug) {
			exitCode = runAnchoreCmd(launcher, outStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--debug", "--html", "gate", "--policy", targetPolicyFile, "--imagefile", targetImageFile);
		    } else {
			exitCode = runAnchoreCmd(launcher, outStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--html", "gate", "--policy", targetPolicyFile, "--imagefile", targetImageFile);
		    }
		} else {
		    if (this.debug) {
			exitCode = runAnchoreCmd(launcher, outStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--debug", "--html", "gate", "--imagefile", targetImageFile);
		    } else {
			exitCode = runAnchoreCmd(launcher, outStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--html", "gate", "--imagefile", targetImageFile);
		    }
		}

		listener.getLogger().println("[anchore][info] Done Running Anchore Gates: exitcode="+exitCode);
		
	    }

	    // prep output
	    rc = prepareReportOutput(listener);
	    if (!rc) {
		listener.getLogger().println("[anchore][error] failed to prepare Anchore output reports.");
		return(selectPluginExitStatus(listener));
	    }

	    // store anchore output html files using jenkins archiver (for remote storage as well)
	    listener.getLogger().println("[anchore][info] archiving anchore results.");
	    ArtifactArchiver artifactArchiver = new ArtifactArchiver("AnchoreReport."+euid+"/");
	    artifactArchiver.perform(build, build.getWorkspace(), launcher, listener);

	    listener.getLogger().println("[anchore][info] cleaning up anchore artifacts in workspace.");
	    rc = anchoreCleanup(build, launcher, listener);
	    if (!rc) {
		listener.getLogger().println("[anchore][error] failed to clean up anchore artifacts in workspace.");
		return(selectPluginExitStatus(listener));
	    }
	    
	} catch (RuntimeException e) {
            listener.getLogger().println("[anchore][error] RuntimeException:" + e.toString());
	    return(selectPluginExitStatus(listener));
	    //	    return(false);
        } catch (Exception e) {
            listener.getLogger().println("[anchore][error] Exception:" + e.toString());
	    return(selectPluginExitStatus(listener));
	    //	    return(false);
        } finally {
	    listener.getLogger().println("[anchore][info] Anchore Plugin Finished");
	}

	if (doGate) {
	    if (exitCode == 0) {
		listener.getLogger().println("[anchore][info] Anchore Gate Policy Final Action: GO");

		// add the link in jenkins UI for anchore results
		build.addAction(new AnchoreAction(build, "GO", euid, queriesOutput));

		return(true);
	    } else if (exitCode == 2) {
		listener.getLogger().println("[anchore][warn] Anchore Gate Policy Final Action: WARN");

		// add the link in jenkins UI for anchore results
		build.addAction(new AnchoreAction(build, "WARN", euid, queriesOutput));

		if (bailOnWarn) {
		    return(false);
		} else {
		    listener.getLogger().println("[anchore][info] Final action is WARN but plugin is configured to return success even on policy failure.");
		    return(true);
		}

	    } else {
		listener.getLogger().println("[anchore][warn] Anchore Gate Policy Final Action: STOP");
		
		// add the link in jenkins UI for anchore results
		build.addAction(new AnchoreAction(build, "STOP", euid, queriesOutput));
		
		if (bailOnFail) {
		    return(false);
	    } else {
		    listener.getLogger().println("[anchore][warn] Final action is STOP but plugin is configured to return success even on policy failure.");
		    return(true);
		}
	    }
	} else {
	    // add the link in jenkins UI for anchore results
	    build.addAction(new AnchoreAction(build, "", euid, queriesOutput));
	}
	return(true);
    }

    public boolean anchoreCleanup(AbstractBuild build, Launcher launcher, BuildListener listener) {
	int exitCode=0;
	// clean up the workspace items (as they should have been archived)
	try {
	    deleteFileOrFolder(Paths.get(anchoreWorkspace));
	} catch (Exception e) {
	    e.printStackTrace();
	    listener.getLogger().println("Exception:" + e.toString());
	    return(false);
	}

	// clean up the build in anchore (if cleanup is set in config)
	exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "exec", containerId, "rm", "-rf", "/root/anchore."+euid);
	if (exitCode != 0) {
	    listener.getLogger().println("[anchore][error] failed to cleanup build artifacts inside Anchore container.");
	    return(false);
	}

	if (doCleanup) {
	    for (String imgId : anchoreInputImages) {
		if (this.debug) {
		    exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "--debug", "toolbox", "--image", imgId, "delete", "--dontask");
		} else {
		    exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "exec", containerId, "anchore", "toolbox", "--image", imgId, "delete", "--dontask");
		}

	    }
	}

	return(true);
    }

    public static void deleteFileOrFolder(final Path path) throws IOException {
	Files.walkFileTree(path, new SimpleFileVisitor<Path>(){
		@Override public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs)
		    throws IOException {
		    Files.delete(file);
		    return CONTINUE;
		}

		@Override public FileVisitResult visitFileFailed(final Path file, final IOException e) {
		    return handleException(e);
		}

		private FileVisitResult handleException(final IOException e) {
		    e.printStackTrace(); // replace with more robust error handling
		    return TERMINATE;
		}

		@Override public FileVisitResult postVisitDirectory(final Path dir, final IOException e)
		    throws IOException {
		    if(e!=null)return handleException(e);
		    Files.delete(dir);
		    return CONTINUE;
		}
	    });
    };

    public boolean prepareReportOutput(BuildListener listener) {
	BufferedWriter bw;
	BufferedReader br;
	try{
	    // CSS
	    bw = new BufferedWriter(new FileWriter(new File(anchoreWorkspace, "anchore.css")));
	    // anchore colors: main:blue #3c7fe2 main:grey #d9e1e2 main:yellow #EEDC00 sec:blue #5BC2E7 sec:green #00B388 sec:navygrey #425563
	    String css = "table {\n"
		+"    border-collapse: collapse;\n"
		+"    width: 100%;\n"
		+"}\n"
		+"th, td {\n"
		+"    text-align: left;\n"
		+"    padding: 8px;\n"
		+"    transition: all 0.3s;\n"
		+"}\n"
		+"tr:nth-child(even){background-color: #eaf2f3}\n"
		+"th {\n"
		+"    background-color: #3c7fe2;;\n"
		+"    color: #EEDC00;\n"
		+"}\n"
		+"tr td:hover { background: #5BC2E7; color: #FFFFFF; }\n";
	    bw.write(css);
	    bw.close();

	    // style append to anchore outputs
	    for (String oFile : oFiles) {
		File inFile = new File(anchoreWorkspace, oFile + ".html");
		if (inFile.exists()) {
		    if (inFile.length() > 0) {
			br = new BufferedReader(new FileReader(inFile));
			bw = new BufferedWriter(new FileWriter(new File(anchoreWorkspace, oFile + "_format.html")));
			bw.write("<link rel=\"stylesheet\" type=\"text/css\" href=\"anchore.css\">\n");
			String line = null;
			while ((line = br.readLine()) != null) {
			    bw.write(line + "\n");
			}
			bw.close();
			br.close();
		    }
		    deleteFileOrFolder(Paths.get(anchoreWorkspace + "/"+oFile+".html"));
		}
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	    listener.getLogger().println("Exception:" + e.toString());	    
	    return(false);
	}

	return(true);
    }

    public boolean anchoreSetup(AbstractBuild build, Launcher launcher, BuildListener listener) {
	try {
	    int exitCode = 0;
	    boolean rc = false;
	    final EnvVars env = build.getEnvironment(listener);

	    oFiles = new ArrayList<String>();
	    anchoreInputImages = new ArrayList<String>();
	    
	    workspace = env.expand("${WORKSPACE}");
	    buildId = String.valueOf(build.getNumber());
	    //euid = build.getExternalizableId();
	    euid = build.getParent().getDisplayName() + "_" + buildId;
	    anchoreWorkspace = workspace + "/AnchoreReport."+euid;
	    containerId = getDescriptor().getContainerId();
	    containerImageId = getDescriptor().getContainerImageId();
	    debug = getDescriptor().getDebug();
	    localVol = getDescriptor().getLocalVol();
	    useSudo = getDescriptor().getUseSudo();

	    queries = new TreeMap<String, String>();
	    queries.put("query1", query1);
	    queries.put("query2", query2);
	    queries.put("query3", query3);
	    queries.put("query4", query4);

	    // set up output directory
	    File htmlDir = new File(anchoreWorkspace);
	    if (!htmlDir.exists()) {
		htmlDir.mkdir();
	    }

	    if (anchoreLogFile == null) {
		anchoreLogFile = new File(anchoreWorkspace, "anchore.log");
		anchoreLogFile.createNewFile();
	    }
	    if (anchoreLogStream == null) {
		if (debug) {
		    anchoreLogStream = listener.getLogger();
		} else {
		    anchoreLogStream = new PrintStream(anchoreLogFile, "UTF-8");
		}
	    }

	    rc = runAnchoreContainer(launcher, listener);
	    if (!rc) {
		listener.getLogger().println("[anchore][error] failed to (re)launch backing Anchore container.");
		return(false);
	    }


	    // set up input
	    anchoreImageFile = new File(workspace, name);
	    if (!anchoreImageFile.exists()) {
		listener.getLogger().println("[anchore][error] cannot locate anchore image list file (needs to be created prior to anchore plugin build step): " + anchoreImageFile.getAbsolutePath());
		return(false);
	    }

	    if (policyName != null) {
		anchorePolicyFile = new File(workspace, policyName);
		if (!anchorePolicyFile.exists()) {
		    listener.getLogger().println("[anchore][warn] policy file does not exist ("+ anchorePolicyFile.getAbsolutePath()+"), using anchore default policy.");
		}
	    }

	    oFiles.add("anchore_gates");
	    oFiles.add("query1");
	    oFiles.add("query2");
	    oFiles.add("query3");
	    oFiles.add("query4");

	    gatesOutputFile = new File(htmlDir, "anchore_gates.html");

	    // stage the input files
	    exitCode = runAnchoreCmd(launcher, listener.getLogger(), listener.getLogger(), "docker", "exec", containerId, "mkdir", "-p", "/root/anchore."+euid);
	    if (exitCode != 0) {
		listener.getLogger().println("[anchore][error] failed to create build artifact directory inside Anchore container.");
		return(false);
	    }

	    File stagedImageFile = new File(anchoreWorkspace, "staged_images."+euid);
	    BufferedWriter bw = new BufferedWriter(new FileWriter(stagedImageFile));
	    BufferedReader br = new BufferedReader(new FileReader(anchoreImageFile));
	    String line = null;
	    while ((line = br.readLine()) != null) {
		String[] kv = line.split(" ");
		String imgId;
		try {
		    imgId = kv[0];
		} catch (Exception e) {
		    imgId = null;
		}
		
		if (imgId != null) {
		    String targetFile = "";
		    try {
			String dfile = kv[1];
			targetFile = "/root/anchore."+euid+"/dfile."+imgId;
			exitCode = runAnchoreCmd(launcher, listener.getLogger(), listener.getLogger(), "docker", "cp", dfile, containerId+":"+targetFile);
		    } catch (Exception e) {
		    }
		    bw.write(imgId + " " + targetFile + "\n");
		    anchoreInputImages.add(imgId);
		}
	    }
	    br.close();
	    bw.close();

	    targetImageFile = "/root/anchore."+euid+"/images";
	    exitCode = runAnchoreCmd(launcher, listener.getLogger(), listener.getLogger(),"docker", "cp", stagedImageFile.getAbsolutePath(), containerId+":"+targetImageFile);

	    if (anchorePolicyFile != null && anchorePolicyFile.exists()) {
		targetPolicyFile = "/root/anchore."+euid+"/policy";
		exitCode = runAnchoreCmd(launcher, listener.getLogger(), listener.getLogger(), "docker", "cp", anchorePolicyFile.getAbsolutePath(), containerId+":"+targetPolicyFile);
	    }

	} catch (RuntimeException e) {
	    e.printStackTrace();
            listener.getLogger().println("RuntimeException:" + e.toString());
	    return(false);
        } catch (Exception e) {
	    e.printStackTrace();
            listener.getLogger().println("Exception:" + e.toString());
	    return(false);
        } finally {
	    listener.getLogger().println("[anchore][info] setup complete.");
	}

	return(true);
    }

    public boolean isAnchoreRunning(Launcher launcher, BuildListener listener) {
	int exitCode = 0;

	exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "start", containerId);
	if (exitCode != 0) {
	    return(false);
	}
	return(true);

    }

    public boolean isAnchoreImageAvailable(Launcher launcher, BuildListener listener) {
	int exitCode = 0;

	exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "inspect", containerImageId);
	if (exitCode != 0) {
	    return(false);
	}
	return(true);

    }

    public boolean runAnchoreContainer(Launcher launcher, BuildListener listener) {
	int exitCode = 0;	

	if (!isAnchoreRunning(launcher, listener)) {
	    if (isAnchoreImageAvailable(launcher, listener)) {

		if (localVol != null && !localVol.isEmpty()) {
		    exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "run", "-d", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", localVol+":/root/.anchore", "--name", containerId, containerImageId);
		} else {
		    exitCode = runAnchoreCmd(launcher, anchoreLogStream, anchoreLogStream, "docker", "run", "-d", "-v", "/var/run/docker.sock:/var/run/docker.sock", "--name", containerId, containerImageId);
		}

	    } else {
		// image is not available
		listener.getLogger().println("[anchore][error] anchore container not running and anchore image ("+containerImageId+") is not available on local dockerhost");
		return(false);
	    }
	} else {
	    listener.getLogger().println("[anchore][info] anchore container is running");
	    exitCode = 0;
	}

	if (exitCode == 0) {
	    listener.getLogger().println("[anchore][info] anchore container has been launched");
	    return(true);
	}
	listener.getLogger().println("[anchore][error] anchore container ("+containerId+") not running and failed to launch anchore container ("+containerImageId+") image from scratch.");
	return(false);	    
    }

    public int runAnchoreCmd(Launcher launcher, PrintStream soutStream, PrintStream serrStream, String... cmd) {
	int exitCode = 0;
	ArgumentListBuilder args = new ArgumentListBuilder();
	
	if (this.useSudo) {
	    args.add("sudo");
	}
	for (String cmdstr : cmd) {
	    for (String cmdlet : cmdstr.split(" ")) {
		args.add(cmdlet);
	    }
	}

	Launcher.ProcStarter ps = launcher.launch();
	ps.cmds(args);
	ps.stdin(null);
	ps.stderr(serrStream);
	ps.stdout(soutStream);

	try {
	    exitCode = ps.join();
	} catch (Exception e) {
	    if (soutStream != null) {
		soutStream.println("command returned non-zero exitcode: " + exitCode);
	    }
	    return(1);
	}

	return(exitCode);
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static class DescriptorImpl extends BuildStepDescriptor<Builder> {
        private boolean debug;
        private boolean enabled;
	private String containerImageId;
	private String containerId;
	private String localVol;
	private boolean useSudo;

        public DescriptorImpl() {
            load();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

	public String getDisplayName() {
            return "Anchore Container Image Scanner";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
	    debug = formData.getBoolean("debug");
	    enabled = formData.getBoolean("enabled");
	    useSudo = formData.getBoolean("useSudo");
	    containerImageId = formData.getString("containerImageId");
	    containerId = formData.getString("containerId");
	    localVol = formData.getString("localVol");
	    
            save();
            return super.configure(req,formData);
        }

	public boolean getDebug() {
            return debug;
        }
	public boolean getEnabled() {
            return enabled;
        }
	public boolean getUseSudo() {
            return useSudo;
        }
	public String getContainerImageId() {
	    return containerImageId;
	}
	public String getContainerId() {
	    return containerId;
	}
	public String getLocalVol() {
	    return localVol;
	}
    }

}

