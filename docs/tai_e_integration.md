Tai-e Integration (Operational Guide)
====================================

This guide documents the supported Tai-e integration path for object-sensitive
pointer analysis in bean-vuln. It is intentionally minimal and verified against
Tai-e's official documentation.

Prerequisites
-------------
- Java 17+ installed (required to build Tai-e)
- Git installed
- Gradle (optional; the project includes `gradlew`)

Official references:
- Command-line options: https://tai-e.pascal-lab.net/docs/current/reference/en/command-line-options.html
- Pointer analysis options: https://tai-e.pascal-lab.net/docs/current/reference/en/pointer-analysis-framework.html
- Releases: https://github.com/pascal-lab/Tai-e/releases

Current upstream note
---------------------
Recent Tai-e releases do not publish pre-built JAR assets. The README still
mentions releases, but the reliable path is to build the fat JAR from source.

Build from source (recommended)
-------------------------------
1) Clone Tai-e:

   git clone https://github.com/pascal-lab/Tai-e.git
   cd Tai-e
   git submodule update --init --recursive

2) Build the fat JAR:

   Linux/macOS:
     ./gradlew fatJar

   Windows:
     gradlew.bat fatJar

3) Verify the output:

   ls build/tai-e-all-*.jar
   # Some builds place it under build/libs
   ls build/libs/tai-e-all.jar

   If only one path exists, use that. The CLI accepts either the jar path
   directly or the containing directory.

   java -jar build/tai-e-all-*.jar --help

4) Point TAI_E_HOME at the JAR (either works):

   export TAI_E_HOME="/path/to/Tai-e/build/tai-e-all-<version>.jar"
   # or
   export TAI_E_HOME="/path/to/Tai-e/build"

Optional helper script
----------------------
You can use the repo helper:

  scripts/setup_tai_e.sh

This clones Tai-e, initializes the `java-benchmarks` submodule, builds the fat
JAR, and sets up a stable symlink in
`~/tai-e-infrastructure/jars/tai-e-all.jar`.

Taint config template
---------------------
We ship a minimal Tai-e taint configuration template:

  configs/tai_e/taint/web-vulnerabilities.yml

It is not exhaustive; extend it for your application.

bean-vuln CLI usage
-------------------
Activate your venv (once), install the package, then use the CLI directly:

  source venv_bean_311/bin/activate
  pip install -e .

Basic usage (pointer analysis only):

  bean-vuln tests/samples/VUL024_ExpressionLanguageInjection.java \
    --summary --out analysis/cli_el_html.json \
    --html-report analysis/html_report_el \
    --joern-dataflow --joern-timeout 120 \
    --tai-e

Enable Tai-e taint analysis (uses the template if present):

  bean-vuln tests/samples/VUL024_ExpressionLanguageInjection.java \
    --summary --out analysis/cli_el_html.json \
    --html-report analysis/html_report_el \
    --joern-dataflow --joern-timeout 120 \
    --tai-e --tai-e-taint

Override taint config:

  --tai-e-taint-config /path/to/taint-config.yml

Notes
-----
- Tai-e recommends analyzing bytecode (.class/.jar) rather than source.
- If a target file has no main method, bean-vuln generates a wrapper entrypoint
  automatically for Tai-e analysis.
- Tai-e's bundled java-benchmarks currently target Java 8. On machines with
  newer JDKs, prefer: `--tai-e-java-version 8 --tai-e-no-prepend-jvm`.
- The CLI accepts `--tai-e-home` pointing to either the JAR or its directory.
- If `bean-vuln` is not on PATH, use `./bean-vuln` from the repo root or
  `./venv_bean_311/bin/bean-vuln`.
