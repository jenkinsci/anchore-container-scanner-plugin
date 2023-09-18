# Local development testing
## Deploying a test build

A build can be executed using the Makefile command `make build`

It is important you bump the version in `pom.xml` prior to starting a build.

The build will run some tests, linting and if all compliant will produce a `.hpi` file in `anchore-container-scanner-plugin/target/anchore-container-scanner.hpi`

You can upload this .hpi file into Jenkins using the `Deploy Plugin` section in `Dashboard > Manage Jenkins > Plugins > Advanced settings`.

> ** You *must* restart Jenkins for the new plugin to take effect, every time any plugin is changed**

You should check that the Anchore Container Scanner plugin settings pane appears in the `Manage Jenkins > System` page. 
Sometimes the plugin install borks and you need to uninstall it within Jenkins (restart Jenkins), rebuild it (`make build`) and re-install it (restart Jenkins).

## Configuring the plugin within Jenkins

Run Anchore Enterprise locally so it is available on your machines localhost.

Within Jenkins go to `Manage Jenkins > System` and find the Anchore settings section.

For `Anchore Enterprise URL` enter `http://host.docker.internal:8228/v2`

Tick `Enable DEBUG logging` for testing as it helps troubleshooting.


## Setting up a test job

Each job can have its own Enterprise override configuration. This can be useful if A/B testing APIs or other systems within Enterprise.

From the Jenkins Dashboard click `New Item`, enter a name, then select `Freestyle project`.

The way the Anchore plugin works, is by reading a line of image tags from a file, and sending those to Enterprise for analysis. By default this file is called `anchore_images`.

This is usually populated by a real test workload, but we can mock it by adding a `Build step` of type `Execute Shell`. Then enter something like the following:

```
echo 'alpine:latest' > anchore_images
echo 'node:5.5-slim' >> anchore_images
```

> These images must be pullable by Enterprise, so if they're private ensure you have registry credentials within Enterprise. Registry credentials within Enterprise will also help bypass the Docker pull rate limit.

Then add a `Build Step` of `Anchore Container Image Scanner`, here you can override any of the default settings, but usually the default config will be enough.

Save the new `Freestyle Job` and it will appear in the Dashboard. From here you can execute it by clicking `Build Now`

Anchore will gate the Job based on if the images passed the specified/default policy. Once a build is complete a new tab called `Anchore Report` will appear in the left hand menu.
