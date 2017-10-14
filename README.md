Anchore Jenkins Plugin
======================

Anchore is a container inspection and analytics platform to enable
operators to deploy containers with confidence. The Anchore toolset in
this repository provides the ability to inspect, reason about, and
evaluate policy against containers present on the local Docker host.

The Anchore Jenkins Plugin enables jenkins users the ability to add a
build step to a jenkins job that executes anchore analysis, gate
policy evaluation, image scanning, and customizable anchore container
image queries.

Requirements:

1) Jenkins installed and configured either as a single system, or with multiple configured jenkins worker nodes

2) Each host on which jenkins jobs will run must have docker installed and the jenkins user (or whichever user you have configured jenkins to run jobs as) must be allowed to interact with docker (either directly or via sudo)

3) Each host on which jenkins jobs will run must have the latest anchore container image installed in the local docker host.  To install, run 'docker pull anchore/jenkins:latest' on each jenkins host to make the image available to the plugin.  The plugin will start an instance of the anchore/jenkins:latest docker container named 'jenkins_anchore' by default, on each host that runs a jenkins job that includes an Anchore Container Image Scanner build step.

To install the plugin manually:

1) compile the plugin by running 'mvn package' in the anchore-container-scanner-plugin source directory

2) install the resulting 'target/anchore-container-scanner.hpi' plugin into jenkins, using the standard jenkins plugin upload procedure

3) under 'Manage Jenkins' -> 'Configure System', locate the 'Anchore' section and be sure to select 'Enable Anchore Scanning' radio box, and save

4) to use the plugin

   a) create a new jenkins job (or configure an exiting job) and you can now add an 'Anchore Container Image Scanner' build step or
  
   b) invoke anchore container scanner plugin in a pipeline script. Following is a sample code snippet. For more options refer to 'Pipeline Syntax' -> 'Step Reference' 
   ```
   node {
     def imageLine = '6cba161501c8' + ' ' + env.WORKSPACE + '/DockerFile'
     writeFile file: 'anchore_images', text: imageLine
     anchore name: 'anchore_images', engineRetries: '300', inputQueries: [[query: 'list-packages all'], [query: 'list-files all'], [query: 'cve-scan all'], [query: 'show-pkg-diffs base']]
   }
   ```

For more information, please visit the anchore plugin wiki at https://wiki.jenkins-ci.org/display/JENKINS/Anchore+Container+Image+Scanner+Plugin or https://www.anchore.com



