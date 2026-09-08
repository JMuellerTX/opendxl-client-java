# OpenDXL Java Client

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.opendxl/dxlclient/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.opendxl/dxlclient)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Actions Status](https://github.com/opendxl/opendxl-client-java/workflows/Build/badge.svg)](https://github.com/opendxl/opendxl-client-java/actions)

## Overview

The OpenDXL Java Client enables the development of applications that connect to the [McAfee Data Exchange Layer](http://www.mcafee.com/us/solutions/data-exchange-layer.aspx) messaging fabric for the purposes of sending/receiving events and invoking/providing services .

## Documentation

See the [Wiki](https://github.com/opendxl/opendxl-client-java/wiki) for an overview of the Data Exchange Layer (DXL), the OpenDXL Java client, and samples.

See the [Java Client SDK Documentation](https://opendxl.github.io/opendxl-client-java/docs) for installation instructions, API documentation, and samples.

## Installation

To start using the OpenDXL Java client:

* Download the [Latest Release](https://github.com/opendxl/opendxl-client-java/releases/latest)
* Extract the release .zip (Windows) or .tar (Linux) file
* View the `README.html` file located at the root of the extracted files.
  * The `README` links to the SDK documentation which includes installation instructions, API details, and samples.
  * The SDK documentation is also available on-line [here](https://opendxl.github.io/opendxl-client-java/docs).

## Maven Repository

The [OpenDXL Java Client Maven Repository](https://search.maven.org/artifact/com.opendxl/dxlclient) on Maven
Central carries the upstream releases; the newest one there is 0.2.6 (December 2020) and has none of the fixes
listed under [Branches](#branches).

**This fork is not published to Maven Central.** The `com.opendxl` namespace there is proven by control of the
opendxl.com domain and belongs to the upstream project. The fork's artifacts keep the same coordinates - so the
jar drops into an existing build - and carry a `-fork.n` version marker, and they are published to this
repository's GitHub Packages registry and attached to its
[releases](https://github.com/derjochenmueller/opendxl-client-java/releases).

Maven:

```xml
<dependency>
  <groupId>com.opendxl</groupId>
  <artifactId>dxlclient</artifactId>
  <version>0.2.9-fork.1-jdk11</version>
</dependency>
```
or Gradle:
```groovy
compile 'com.opendxl:dxlclient:0.2.9-fork.1-jdk11'
```

## Branches

The repository is maintained as one branch per supported JDK. Every branch pins its JDK
with a Gradle Java toolchain (`java.toolchain.languageVersion` in `build.gradle`), compiles
the library for exactly that Java release and runs its GitHub Actions workflow on that JDK
only. Missing JDKs are downloaded automatically by the
[foojay toolchain resolver](https://github.com/gradle/foojay-toolchains) configured in
`settings.gradle`, so `./gradlew assemble` works on any branch regardless of the locally
installed JDK (the resolver stays at 0.9.0, the last version that runs on a Java 8 or 11
Gradle JVM).

| Branch   | JDK / bytecode level | Notes                                                                    |
|----------|----------------------|--------------------------------------------------------------------------|
| `master` | 21                   | Main development line, language level 21 (`--release 21`)                |
| `jdk17`  | 17                   | `--release 17`                                                           |
| `jdk11`  | 11                   | `--release 11`                                                           |
| `jdk8`   | 8                    | Java 8 bytecode via `sourceCompatibility`/`targetCompatibility`          |

The library API (packages, classes, signatures) and the DXL wire format are identical on all
branches; the branches differ only in build settings and in the Java release the bytecode is
compiled for. Branch specific settings are marked with comments in `build.gradle` and
`.github/workflows/main.yml`. The `TlsCompatibility` workaround (re-enabling the
`TLS_RSA_*` cipher suites that OpenDXL brokers require) is needed on every JDK line since
the 2025 JDK updates and is therefore not branch specific.

Workflow for changes:

1. Fix on `master` first and let its workflow run go green.
2. Cherry-pick the commit into the older branches where it applies, from newest to oldest:
   `jdk17` -> `jdk11` -> `jdk8`, keeping the reference to the original commit:

   ```sh
   git checkout jdk17 && git cherry-pick -x <sha>
   git checkout jdk11 && git cherry-pick -x <sha>
   git checkout jdk8  && git cherry-pick -x <sha>
   ```

3. Push each branch; the branch's own workflow run (`build`, one job on the branch's JDK,
   which needs the OpenDXL broker and squid containers of the workflow) must be green
   before the change is considered done on that branch.

Local build on any branch: `./gradlew assemble`. The test suite needs a provisioned client
configuration in `clientconfig/` (see `.github/workflows/main.yml`): `./gradlew test`.

## Bugs and Feedback

For bugs, questions and discussions please use the [Github Issues](https://github.com/opendxl/opendxl-client-java/issues).

## LICENSE

Copyright 2018 McAfee, LLC

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
