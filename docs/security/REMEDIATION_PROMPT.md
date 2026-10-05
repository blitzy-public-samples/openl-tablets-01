| Category | Low | High |
| --- | --- | --- |
| Production | 1712 | 3134 |
| Test | 4660 | 8180 |
| Configuration and build | 191 | 383 |
| Documentation | 188 | 345 |
| Total | 6751 | 12042 |
| Human decision (SEC-03, SEC-14; excluded from Total) | 974 | 1681 |

OBJECTIVE: Each of these 37 Open findings of `SECURITY_FINDINGS.md` MUST be fixed under the constraints below, through its own `CRITICAL Directive:` and in this order: DEP-08, DEP-09, DEP-10, SEC-01, SEC-02, SEC-20, DEP-11, DEP-12, SEC-04, DEP-13, DEP-14, DEP-15, SEC-10, SEC-26, SEC-27, SEC-33, SEC-08, SEC-13, SEC-34, SEC-07, SEC-23, SEC-06, SEC-09, SEC-17, SEC-05, SEC-31, SEC-32, SEC-16, SEC-29, DEP-16, SEC-11, SEC-30, SEC-12, SEC-22, SEC-28, SEC-15, SEC-25.

CONSTRAINTS:
- Validate fixes only through `mvn clean install` and in-JVM unit or integration tests that use mocked requests or MockMvc.
- Never start services or run exploits. Never send requests to any host other than the declared package registries (Maven Central, Shibboleth, JBoss, npm registry), the Node.js distribution host `nodejs.org` and scanner database sources.
- Preserve all REST endpoints, `user.mode` values, existing property keys and module boundaries.
- Make minimal changes only, and add each regression test to the existing test module of the class it covers.
- The validation command is `mvn clean install -P '!itest' -Dsurefire.excludesFile=<path>`. The excludes file MUST sit outside the working tree and list exactly `**/MailConfigValidatorTest.java`; every directive and every gate MUST use this command.
- The `itest` profile, which holds the ITEST suites and both archetype builds (`pom.xml:1833-1836`), and `MailConfigValidatorTest` MUST NOT run, because they start Kafka, Jetty, identity and storage containers or an in-JVM SMTP server.
- `-DskipTests`, `-o`, `npm_config_offline`, the `npm.*.skip` properties (`pom.xml:226-228`), `skip.installnodenpm` and `skip.npm` MUST NOT be used. The Vitest suites of `STUDIO/studio-ui` MUST run, so the SEC-04 UI changes are validated.
- Maven artifacts MUST come only from the declared repositories: Maven Central, `shibboleth-releases` and `jboss-releases`. npm 12.0.2 (`pom.xml:225`) and every npm package MUST come only from the npm registry `registry.npmjs.org`.
- The build MUST use the Node v24.21.0 archive (`pom.xml:224`) from the `frontend-maven-plugin` cache in the local Maven repository (`com/github/eirslett/node/`) whenever that cache holds it. When the cache lacks it, the plugin downloads it from `nodejs.org`, its default download root. The build MUST NOT set `nodeDownloadRoot` and MUST NEVER fetch Node.js from any other host.
- Baseline: before the first directive, the validation command MUST run once on the unchanged tree. When it fails, no directive changes code: every directive is recorded as failed with the baseline error, and the Project Guide lists the failure and what unblocks it, for example a Node v24.21.0 archive missing from the plugin cache whose download from `nodejs.org` failed.
- Version lookups read only the `maven-metadata.xml` of a declared Maven repository and `npm view <package> versions` against `registry.npmjs.org`.
- Migration notes: the Default-changing directives create `docs/security/MIGRATION_NOTES.md`, and the remediation run is the only run that creates it. The first Default-changing directive that runs writes the file and its header; every Default-changing directive adds one entry stating what flipping its default breaks and how users upgrade.
- Switch pattern for every Default-changing directive except SEC-20: each new property goes into the named `openl-default.properties` beside its neighbours, with a comment in the neighbouring style, and its default MUST preserve the audited runtime behavior exactly. Names use dotted lowercase segments with kebab-case words, booleans read `allow-...` or `....enabled`, and every key MUST match `openl.config.key-pattern.allowed` (`DEV/org.openl.spring/resources/openl-default.properties:51`).
- Startup WARN: the named owner class logs one `WARN` line for each insecure condition of the effective configuration, so a partially hardened configuration still warns. Each line names the finding ID, the property and the recommended secure value, as `STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/PasswordEncoderConfig.java:37-60` does.
- Regression tests follow `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/PasswordEncoderConfigTest.java`: every property gets a test at its default and at its secure value, and a finding with two properties also gets one partially hardened test that sets one property secure, keeps the other at its default and asserts the remaining `WARN`. Test classes and methods stay package-private JUnit 5.
- Any code comment a fix adds MUST explain WHY, not WHAT. NEVER log a password, token secret, private key or session identifier.

FAILURE HANDLING:
- When a directive fails its gate after 3 attempts with the same error, revert that directive's changes, record the failure, and continue with the next directive.
- A failed directive never blocks the others.
- Gate scope: a directive's gate covers only its own finding IDs, and for a Dependency upgrade only the occurrences its upgrade unit owns. A finding owned by another directive NEVER fails, and NEVER reverts, a directive.
- A revert MUST undo only the reverted directive's own edits; edits that other directives made to a shared file stay in place.

PASS GATES:
- The build passes with 100% of existing tests passing.
- Each code or switch fix has at least 1 regression test per property state.
- OWASP Dependency-Check reports zero CVSS ≥ 7.0 findings that have an available fixed version; findings with no fixed version are documented as "no fix available" with the upstream tracking link.
- Gate 1 counts the tests the validation command runs. The ITEST suites, the archetype builds and `MailConfigValidatorTest` are reported as not run, NEVER as passed.
- Gate 2: SEC-20 has no property state, so its gate is the commented-lines diff check of its directive.
- Gate 3 collection: Dependency-Check MUST run through the `owasp` profile as a direct goal, `mvn -B -Powasp org.owasp:dependency-check-maven:13.0.0:aggregate`, with `-Dowasp.failBuildOnCVSS=11 -DversionCheckEnabled=false -DskipTestScope=false -DassemblyAnalyzerEnabled=false -DcentralAnalyzerEnabled=false -DossIndexAnalyzerEnabled=false -DnodeAuditAnalyzerEnabled=false -DyarnAuditAnalyzerEnabled=false -DpnpmAuditAnalyzerEnabled=false`, `-DdataDirectory=<path>` outside the working tree, and `-Dodc.outputDirectory=<path>` with `-Dformats=JSON` so the JSON report is written outside the working tree. Collection MUST NOT pass `-P '!itest'` or `-DskipTests`, so the ITEST modules that own DEP-08 and DEP-12 occurrences stay in scope; as a direct goal it runs no test.
- Gate 3 database update: the first collection run MUST use `-DautoUpdate=true`, reaching only `nvd.nist.gov`, `www.cisa.gov`, `raw.githubusercontent.com` and `dependency-check.github.io`. When that run fails during the update and the data directory already holds a populated database, collection reruns with `-DautoUpdate=false`. With no populated database, gate 3 is recorded as "not executed: database update failed: `<error>`".
- Gate 3 threshold: collection always passes `-Dowasp.failBuildOnCVSS=11`. No CVSS score exceeds 10, so collection never fails on a finding, even after a human enables the SEC-14 gate, and the gate and the register measure the same scope.
- Gate 3 scan failure: with a threshold of 11, a non-zero collection exit after the update is a scan failure (an unreadable database, an analysis error or an unresolvable artifact). Gate 3 is then recorded as "not executed: scan failure: `<error>`". That is NEVER a pass and NEVER a policy failure; it reverts nothing, and the Project Guide lists it.
- Gate 3 enforcement: a checker script outside the working tree reads the collected JSON and owns the gate result. It fails every vulnerability whose CVSS v3.x base score is 7.0 or higher unless an exemption applies. A fix counts as available whenever no exemption applies, including when the fixed version is "not identified in scanner data". The only exemptions, both read from `SECURITY_FINDINGS.md`, are an occurrence the register marks Not-applicable with its evidence and a "no fix available" row that carries the affirmative evidence of an open-ended affected range or an all-line vendor disposition.
- Gate 3 npm scope: collection disables the Dependency-Check Node, Yarn and pnpm audit analyzers, so its report carries no `STUDIO/studio-ui` advisory. For an npm upgrade unit the scoped check therefore reads `npm audit --package-lock-only --json --registry=https://registry.npmjs.org/` run in `STUDIO/studio-ui`, which reads only `package-lock.json`, installs nothing and runs no script, and applies the same CVSS rule and exemptions to the GHSA IDs that unit owns.
- Gate 3 per directive: a Dependency upgrade directive runs the enforcement check only on the occurrences its upgrade unit owns; other directives do not run gate 3.
- Gate 3 final aggregate: after every directive has run, the enforcement check runs once over the whole Dependency-Check report and the `STUDIO/studio-ui` `npm audit` report. Its failures go to the Project Guide hand-off, and it reverts nothing.

PROJECT GUIDE HAND-OFF:
the final Project Guide lists, as human tasks:
- every switch property with its recommended secure value, what flipping it breaks, and the target release;
- every Operator-only finding;
- every failed directive with its error;
- actual generated LOC against the estimate for each finding.
- The target release for every switch flip is 6.6.0, the next minor release after `6.5.0`, unless a directive states otherwise.
- The Operator-only findings are [SEC-18](SECURITY_FINDINGS.md#sec-18), [SEC-19](SECURITY_FINDINGS.md#sec-19), [SEC-21](SECURITY_FINDINGS.md#sec-21) and [SEC-24](SECURITY_FINDINGS.md#sec-24); section 6 of `SECURITY_FINDINGS.md` carries their actions, and no directive changes code for them.
- The guide lists the tests not run (the ITEST suites, the two archetype builds and `MailConfigValidatorTest`) and the behavior no in-JVM test verifies: container-level refusal of an oversized multipart upload (SEC-26).
- The guide lists a baseline failure with what unblocks it, every gate 3 that was not executed with its reason, and the result of the final aggregate gate.
- Human decision [SEC-03](SECURITY_FINDINGS.md#sec-03): no directive was written for SEC-03, and a human MUST decide and apply this recommendation. Estimated LOC: Production: 250–450; Test: 650–1100; Configuration and build: 14–26; Documentation: 10–15.
  - Switch property `rules.block-system-classes`, default `false`, secure value `true`: a constant and accessor in `OpenLSystemProperties` beside `DISPATCHING_VALIDATION` (`DEV/org.openl.rules/src/org/openl/engine/OpenLSystemProperties.java:9-17`), declared in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties` and `WSFrontend/org.openl.rules.ruleservice/resources/openl-default.properties`, following the `dispatching.validation` precedent at `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties:21` and `WSFrontend/org.openl.rules.ruleservice/resources/openl-default.properties:31`. The engine reads external parameters first and the JVM system property second (`OpenLSystemProperties.java:19-27`) and never reads Spring default files.
  - `WARN` owners: `RuleServiceOpenLServiceInstantiationFactoryImpl` for OpenL Rule Services and a Studio startup configuration bean, `STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SystemClassPolicyConfiguration.java`, modelled on `PasswordEncoderConfig`; each logs one `WARN` naming SEC-03, the property and `true` while the value is `false`. `WebStudio` MUST NOT own it, because each user session creates one.
  - Propagation: add the key to the `externalParameters` props of the `ruleServiceInstantiationFactory` bean (`WSFrontend/org.openl.rules.ruleservice/resources/openl-ruleservice-core-beans.xml:18-22`), which `RuleServiceOpenLServiceInstantiationFactoryImpl` passes into compilation (`WSFrontend/org.openl.rules.ruleservice/src/org/openl/rules/ruleservice/core/RuleServiceOpenLServiceInstantiationFactoryImpl.java:50`, `:74`), and copy it in `WebStudio` beside `copyExternalProperty(OpenLSystemProperties.DISPATCHING_VALIDATION)` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/ui/WebStudio.java:185-186`), so every compilation that uses its external properties (`WebStudio.java:869`) receives it.
  - Policy before resolver construction: `XlsBinder.bind` builds the module's `OpenL` and `TypeResolver` (`DEV/org.openl.rules/src/org/openl/rules/lang/xls/XlsBinder.java:189-196`) before the external parameters reach the binding context (`XlsBinder.java:222-223`). The change MUST read the effective policy at the start of `bind` from `parsedCode.getExternalParams()` (`DEV/org.openl.rules/src/org/openl/syntax/code/IParsedCode.java:51`), external parameter first and JVM property second, and pass it through `makeOpenL` (`XlsBinder.java:443`, `:470`) to the `TypeResolver` constructor. The default resolver (`DEV/org.openl.rules/src/org/openl/OpenL.java:44`) reads the JVM property.
  - Policy-aware cache key: the `openls` cache (`XlsBinder.java:135`) is keyed by module URI (`XlsBinder.java:189`), and one `RulesEngineFactory` keeps one `XlsBinder` (`DEV/org.openl.rules/src/org/openl/rules/runtime/RulesEngineFactory.java:186-196`). The key MUST become `XLSX::<uri>::<policy>`, so an `OpenL` built under one policy is NEVER reused under the other and the duplicate check in `registerOpenL` (`XlsBinder.java:141-146`) applies per key.
  - Enforcement in `TypeResolver`: a denied type MUST NEVER be returned through the pre-registered core classes (`DEV/org.openl.rules/src/org/openl/conf/TypeResolver.java:177`, `:184-194`, `:368`), the aliases built from module imports (`TypeResolver.java:346-355`, imports loaded at `XlsBinder.java:457`), the `found` cache (`TypeResolver.java:371-377`), package lookups (`TypeResolver.java:404-419`) or dynamic loading (`TypeResolver.java:421-425`).
  - Member binding: `MethodNodeBinder` target calls (`DEV/org.openl.rules/src/org/openl/binding/impl/MethodNodeBinder.java:255-271`, through `ModuleSpecificOpenMethod.findMethodCaller` at `DEV/org.openl.rules/src/org/openl/binding/impl/module/ModuleSpecificOpenMethod.java:81-83`), the constructor type lookup (`MethodNodeBinder.java:95`) and `IdentifierBinder` field access (`DEV/org.openl.rules/src/org/openl/binding/impl/IdentifierBinder.java:85-147`) MUST refuse a method or field whose declaring type or return type is denied, reading the policy from `bindingContext.getExternalParams()` (`DEV/org.openl.rules/src/org/openl/rules/lang/xls/binding/XlsModuleOpenClass.java:133`, `DEV/org.openl.rules/src/org/openl/binding/impl/BindingContextDelegator.java:189-190`). `MethodSearch.findMethod` stays unchanged.
  - Denied set: `ClassLoader`, `Process`, `ProcessBuilder`, `Runtime`, `System`, `Thread`, `ProcessHandle`, `ThreadGroup`, `java.lang.Class`, and the packages `java.lang.reflect`, `java.lang.invoke`, `javax.script`, `sun.*` and `jdk.*`.
  - Test plan: `DEV/org.openl.rules/test` covers both states on each enforcement path, member binding included (`TypeResolverSecurityTest`, `SystemClassBindingTest`); precedence, where an external parameter at the secure value with the JVM property at the default, and the reverse, are each decided by the external parameter (`SystemClassPolicyPrecedenceTest`); and reuse, where one `RulesEngineFactory` compiles the same module under the default and then the secure policy, and the reverse, each following its own policy (`SystemClassPolicyReuseTest`). Propagation tests in both states go into `WSFrontend/org.openl.rules.ruleservice/test` and `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/ui/` (`SystemClassPolicyPropagationTest`).
  - Risk: the change touches core compiler paths (`XlsBinder`, `TypeResolver`, `MethodNodeBinder` and `IdentifierBinder`), so the full `DEV/` test suite MUST pass with the property at its default before the change is merged.
- Human decision [SEC-14](SECURITY_FINDINGS.md#sec-14): no directive was written for SEC-14, and a human MUST decide and apply this configuration. Estimated LOC: Production: 0–0; Test: 0–0; Configuration and build: 50–90; Documentation: 0–0.
  - The `owasp` profile (`pom.xml:1989-2006`) declares the property `owasp.failBuildOnCVSS` with the value `7` and configures the plugin's `failBuildOnCVSS` as `${owasp.failBuildOnCVSS}`, NEVER as a literal: a literal `<configuration>` value cannot be overridden from the command line, so gate-3 collection would lose its report-only threshold.
  - The profile sets `suppressionFiles` to a new root-level `dependency-check-suppressions.xml`, which holds only verified false positives and no-fix entries with affirmative no-fix evidence, each with `notes` and `until`.
  - The Trivy scan in `.github/workflows/trivy.yml:56-59` adds `--exit-code 1 --severity HIGH,CRITICAL --ignorefile .trivyignore` and NEVER uses `--ignore-unfixed`, because that flag also drops findings whose fixed-version metadata is merely absent.
  - The job checks out no repository files (`.github/workflows/trivy.yml:52-59`), so the same `run` block first writes `.trivyignore` from a workflow-level list. Each entry is the finding ID with an `exp:` date and a comment naming the evidence, and the list holds exactly the IDs exempted in `dependency-check-suppressions.xml`.
  - Verification for the human: the suppression file is well-formed XML in the Dependency-Check suppression namespace, the two exemption lists hold the same IDs, and a collection run with `-Dowasp.failBuildOnCVSS=11` exits 0 while Open CVSS ≥ 7.0 findings remain.
  - Enabling these gates fails CI for every CVSS ≥ 7.0 finding still open after remediation, so the human MUST enable them only once the final aggregate gate reports zero such findings.

---

CRITICAL Directive: Upgrade Spring Boot until the ITEST Tomcat leaves every owned advisory range

- Finding: [DEP-08](SECURITY_FINDINGS.md#dep-08)
- CVE/CWE: CVE-2026-65637, CVE-2026-65905, CVE-2026-53434, CVE-2026-55276, CVE-2026-59083, CVE-2026-59084, CVE-2026-65182, CVE-2026-68525, CVE-2026-65183, CVE-2026-66422, CVE-2026-68569, CVE-2026-65927, CVE-2026-68763, CVE-2026-53404, CVE-2026-73180, CVE-2026-55955, CVE-2026-55956, CVE-2026-50229, CVE-2026-66299
- Severity: Critical 9.8
- Bucket: Dependency upgrade
- Files and classes: `pom.xml:91` (`spring.boot.version` 3.5.16), consumed by the Spring Boot starter declarations at `pom.xml:429-450`. The only consumer of `org.apache.tomcat.embed:tomcat-embed-core` 10.1.55 is `ITEST/itest.spring-boot-web-app`, through `spring-boot-starter-web` and `spring-boot-starter-tomcat` 3.5.16.
- Required fix:
  - MUST set `spring.boot.version` to the lowest Spring Boot release on Maven Central whose `spring-boot-starter-tomcat` resolves `tomcat-embed-core` outside all 19 owned ranges. The register names 10.1.56 and 10.1.58 as fixed Tomcat versions, and CVE-2026-59083 and CVE-2026-59084 have no fixed version in scanner data.
  - MUST find that release by reading `maven-metadata.xml` of `org/springframework/boot/spring-boot-starter-tomcat` on Maven Central and the Tomcat version each candidate POM declares, starting with the 3.5 releases above 3.5.16, and MUST confirm the choice with the scoped gate-3 check.
  - MUST reject every candidate whose POM requires Spring Framework 7, which `pom.xml:93-96` and `pom.xml:101-102` rule out for this tree (compiler release 21, `pom.xml:1304`). When no remaining release clears every range, the directive fails its gate under FAILURE HANDLING and NEVER records "no fix available", because no owned row carries no-fix evidence.
  - NEVER pin `tomcat-embed-core` in a module POM, and NEVER change `spring.framework.version`, which the BOM import at `pom.xml:422-428` manages independently.
- Tests: no new test class; the regression evidence is the scoped gate-3 check. A code change the upgrade forces MUST carry a regression test in the existing test module of the changed class. `ITEST/itest.spring-boot-web-app` stays outside the validation command and is reported as not run.
- Estimated LOC: Production: 0–30; Test: 0–60; Configuration and build: 1–3; Documentation: 0–0
- Pass/fail: the validation command passes, the scoped gate-3 check over the `tomcat-embed-core` occurrences of the 19 listed CVEs reports zero failures, and the collected Dependency-Check report lists none of the 19 IDs against the upgraded `tomcat-embed-core`.

---

CRITICAL Directive: Upgrade Spring Framework until spring-core leaves every owned Open advisory range

- Finding: [DEP-09](SECURITY_FINDINGS.md#dep-09)
- CVE/CWE: CVE-2026-47884, CVE-2026-47890, CVE-2026-47891, CVE-2026-47892, CVE-2026-59313, CVE-2026-59283, CVE-2026-47885, CVE-2026-47886, CVE-2026-47888, CVE-2026-47889, CVE-2026-47893, CVE-2026-59282, CVE-2026-47883, CVE-2026-47887, CVE-2026-59281, CVE-2026-59280, CVE-2026-59314 (Open); CVE-2022-22968, CVE-2024-38820, CVE-2025-22233 (Not-applicable, substituted `spring-context` fixtures)
- Severity: Critical 9.8
- Bucket: Dependency upgrade
- Files and classes: `pom.xml:90` (`spring.framework.version` 6.2.19), imported through `spring-framework-bom` at `pom.xml:422-428`; `org.springframework:spring-core` 6.2.19 resolves in Runtime scope across most `DEV/`, `STUDIO/` and `WSFrontend/` modules. The `@spring.framework.version@` placeholder in `Util/openl-maven-plugin/it/**` takes the root value at invoker time and needs no separate edit.
- Required fix:
  - MUST set `spring.framework.version` to the lowest Spring Framework 6.2 release on Maven Central, at or above 6.2.20, that moves `spring-core` outside the ranges of all 17 Open rows. The register identifies 6.2.20 for 15 rows, and CVE-2026-59313 and CVE-2026-59314 have no fixed version in scanner data.
  - MUST read `maven-metadata.xml` of `org/springframework/spring-framework-bom` on Maven Central for the candidates and MUST confirm the choice with the scoped gate-3 check.
  - NEVER move to the 7.x line: `pom.xml:93-96` and `pom.xml:101-102` keep this tree on Spring Framework 6. When no 6.2 release clears every Open range, the directive fails its gate and NEVER records "no fix available".
  - MUST keep the three Not-applicable `spring-context` rows exempt only through their register evidence; NEVER add a new exemption for them here.
- Tests: no new test class; the regression evidence is the scoped gate-3 check. A code change the upgrade forces MUST carry a regression test in the existing test module of the changed class.
- Estimated LOC: Production: 0–30; Test: 0–60; Configuration and build: 1–3; Documentation: 0–0
- Pass/fail: the validation command passes, the scoped gate-3 check over the `spring-core` occurrences of the 17 Open rows reports zero failures, and the collected Dependency-Check report lists none of those 17 IDs against the upgraded `spring-core`.

---

CRITICAL Directive: Upgrade Spring Integration until spring-integration-core leaves every owned advisory range

- Finding: [DEP-10](SECURITY_FINDINGS.md#dep-10)
- CVE/CWE: CVE-2026-47864, CVE-2026-59324, CVE-2026-59307, CVE-2026-59311, CVE-2026-59293, CVE-2026-47859, CVE-2026-59274, CVE-2026-47856, CVE-2026-47861, CVE-2026-59322, CVE-2026-47862, CVE-2026-47880, CVE-2026-59321, CVE-2026-59292
- Severity: Critical 9.8
- Bucket: Dependency upgrade
- Files and classes: `pom.xml:92` (`spring.integration.version` 6.5.10), consumed by the `spring-integration-jdbc` declaration at `pom.xml:477-481`; `spring-integration-core` 6.5.10 resolves in Runtime scope in `org.openl.security.standalone` and `org.openl.rules.webstudio`.
- Required fix:
  - MUST set `spring.integration.version` to the lowest Spring Integration release on Maven Central that moves `spring-integration-core` outside all 14 owned ranges. The register identifies 6.5.11 for 11 rows, and CVE-2026-59307, CVE-2026-59311 and CVE-2026-59321 have no fixed version in scanner data.
  - MUST read `maven-metadata.xml` of `org/springframework/integration/spring-integration-core` on Maven Central for the candidates, starting with the 6.5 releases above 6.5.10, and MUST confirm the choice with the scoped gate-3 check.
  - MUST reject every candidate whose POM requires Spring Framework 7 (`pom.xml:93-96`). When no remaining release clears every range, the directive fails its gate and NEVER records "no fix available".
- Tests: no new test class; the regression evidence is the scoped gate-3 check. A code change the upgrade forces MUST carry a regression test in the existing test module of the changed class.
- Estimated LOC: Production: 0–30; Test: 0–60; Configuration and build: 1–3; Documentation: 0–0
- Pass/fail: the validation command passes, the scoped gate-3 check over the `spring-integration-core` occurrences of the 14 listed CVEs reports zero failures, and the collected Dependency-Check report lists none of the 14 IDs against the upgraded `spring-integration-core`.

---

CRITICAL Directive: Require JWT authentication on every OpenL Rule Services deployment endpoint

- Finding: [SEC-01](SECURITY_FINDINGS.md#sec-01)
- CVE/CWE: CWE-306
- Severity: Critical 9.8
- Bucket: Code fix
- Files and classes: `JWTValidator.authorize` in `WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/spring/JWTValidator.java:83-85`; the upload, download and delete endpoints of `RulesDeployerRestController` under `/admin/deploy` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/admin/RulesDeployerRestController.java:33-123`); `RuleServicesFilter.skipAuthorization` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/servlet/RuleServicesFilter.java:204-209`); new test `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/spring/JWTValidatorTest.java`.
- Required fix:
  - MUST make `JWTValidator.authorize` validate the bearer token for every path under `/admin/deploy`, so upload, download and delete require authentication whenever `ruleservice.authentication.enabled=true`.
  - MUST keep `/admin/healthcheck/readiness` public; `RuleServicesFilter.skipAuthorization` already exempts `/admin/healthcheck/`, and that method stays unchanged.
  - MUST keep the OpenAPI exemption (`JWTValidator.java:87-89`), the conditional bean (`JWTValidator.java:34`) and the `ruleservice.deployer.enabled = false` default (`WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties:22-24`) unchanged, and NEVER widen this change to other `/admin/` paths: SEC-11 owns the information endpoints.
- Tests: new package-private `JWTValidatorTest` in `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/spring/`, modelled on `RuleServicesFilterTest`. It builds `JWTValidator` from a `MockEnvironment` whose JWKS is a key set written to a JUnit `@TempDir` and referenced as a `file:` location, signs its tokens in-JVM with the matching test key, and drives `authorize` with mocked `HttpServletRequest` objects. It proves that an unauthenticated upload, download or delete under `/admin/deploy` is refused, that the same requests with a valid token are authorized, and that `/admin/healthcheck/readiness` is authorized without a token. `ITEST/itest.security/test/org/openl/test/JWTValidatorTest.java` is outside the validation command and never counts for this gate.
- Estimated LOC: Production: 20–40; Test: 80–160; Configuration and build: 0–0; Documentation: 0–0
- Pass/fail: the validation command passes, and `JWTValidatorTest` in `WSFrontend/org.openl.rules.ruleservice.ws/test` proves that an unauthenticated call to each deploy endpoint is refused while `/admin/healthcheck/readiness` is served.

---

CRITICAL Directive: Add remote-access switches for anonymous OpenL Studio single mode and unauthenticated OpenL Rule Services

- Finding: [SEC-02](SECURITY_FINDINGS.md#sec-02)
- CVE/CWE: CWE-1188
- Severity: Critical 9.8
- Bucket: Default-changing fix
- Files and classes: `SingleSecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SingleSecurityConfig.java:27-31`); `RuleServicesFilter` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/servlet/RuleServicesFilter.java:68-99`); `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties:23-31`; `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties:59`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/SingleSecurityConfigTest.java` and `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/servlet/RuleServicesFilterTest.java`; `docs/security/MIGRATION_NOTES.md`, whose header this directive's LOC row carries.
- Required fix:
  - At `security.single.allow-remote-access=false`, OpenL Studio in `user.mode=single` MUST refuse every request whose remote peer is not a loopback address with 403 and MUST serve loopback requests unchanged.
  - At `ruleservice.authentication.allow-anonymous-remote=false`, OpenL Rule Services with `ruleservice.authentication.enabled=false` MUST refuse every request whose remote peer is not a loopback address with 403, except the `/admin/healthcheck/` paths that `RuleServicesFilter.skipAuthorization` keeps public, and MUST serve loopback requests unchanged.
  - Both checks MUST read the connection's original peer address before forwarded-header processing, so a client-supplied `X-Forwarded-For` value NEVER passes them.
  - At the defaults (`true`) both applications MUST behave exactly as today.
- Switch:
  - `security.single.allow-remote-access` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`, beside the `security.single.*` keys (`:35-43`); default `true`; recommended secure value `false`.
  - `ruleservice.authentication.allow-anonymous-remote` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`, beside `ruleservice.authentication.enabled` (`:59`); default `true`; recommended secure value `false`.
  - `WARN` owners: `SingleSecurityConfig` logs one line when `user.mode=single` and remote access is allowed; `RuleServicesFilter` initialization logs one line when `ruleservice.authentication.enabled=false` and anonymous remote access is allowed. Each line names SEC-02, its property and `false`.
  - `docs/security/MIGRATION_NOTES.md`: create the file with its header and add the SEC-02 entry. Flipping either value refuses anonymous remote callers; OpenL Studio users move to `multi`, `ad`, `saml` or `oauth2` mode, and OpenL Rule Services clients enable JWT authentication or reach the application through a loopback proxy.
- Tests: `SingleSecurityConfigTest` and `RuleServicesFilterTest` with mocked requests whose remote address is set explicitly. Default: a request from a non-loopback address is served in each application. Secure: a request from a non-loopback address is refused and a loopback request is served in each application, and a non-loopback `/admin/healthcheck/readiness` request stays served in OpenL Rule Services. Partially hardened: one application at its secure value with the other at its default, asserting the remaining startup `WARN`.
- Estimated LOC: Production: 80–140; Test: 200–360; Configuration and build: 8–16; Documentation: 10–17
- Pass/fail: the validation command passes, `SingleSecurityConfigTest` and `RuleServicesFilterTest` prove the default, secure and partially hardened states above, each insecure condition logs its own `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-02 entry.

---

CRITICAL Directive: Add a commented secure profile to the reference compose stack

- Finding: [SEC-20](SECURITY_FINDINGS.md#sec-20)
- CVE/CWE: CWE-1188
- Severity: Critical 9.8
- Bucket: Default-changing fix
- Files and classes: `compose.yaml:11-23` and `compose.yaml:39-57` (JDWP ports 5005 and 5006 with `-Xrunjdwp` options, `cors.allowed.origins: "*"`, `RULESERVICE_DEPLOYER_ENABLED: "true"`, a literal repository password), `compose.yaml:93-101` (a literal database password, published port 5432), `compose.yaml:136` (the same literal password in the OpenL Studio settings), `compose.yaml:236` (index-page login hint); `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - MUST add to `compose.yaml` only a commented secure profile, every added line starting with `#` after optional spaces. The profile shows the same services without a CORS wildcard, without JDWP options or debug port mappings, with the database password read from an operator-supplied environment variable that holds a generated value instead of a literal, with `RULESERVICE_DEPLOYER_ENABLED` set to `"false"`, and without a published PostgreSQL port.
  - NEVER change, reorder or remove any existing `compose.yaml` line; the existing services stay byte-identical.
  - NEVER add a property, startup `WARN` or JVM test for SEC-20.
- Switch: not applicable (C10). No property, startup `WARN` or JVM test exists for a commented `compose.yaml` profile. The `docs/security/MIGRATION_NOTES.md` entry states that the reference stack stays a development stack, how to adopt the commented profile, and that adopting it removes remote debugging, the wildcard CORS origin, the enabled deployer and the published database port.
- Tests: none; the gate is the commented-lines diff check (C10).
- Estimated LOC: Production: 0–0; Test: 0–0; Configuration and build: 28–48; Documentation: 8–15
- Pass/fail: in this directive's own diff of `compose.yaml`, every added line starts with `#` after optional spaces and no existing line changes; `docs/security/MIGRATION_NOTES.md` holds the SEC-20 entry; the validation command passes.

---

CRITICAL Directive: Upgrade Spring Security until core, LDAP and OAuth2 resource-server leave every owned range

- Finding: [DEP-11](SECURITY_FINDINGS.md#dep-11)
- CVE/CWE: CVE-2026-59270, CVE-2026-41707, CVE-2026-47841, CVE-2026-47842, CVE-2026-59276
- Severity: Critical 9.1
- Bucket: Dependency upgrade
- Files and classes: `pom.xml:100` (`spring.security.version` 6.5.11), imported through `spring-security-bom` at `pom.xml:462-468`; each CVE row owns three occurrences, `spring-security-core`, `spring-security-ldap` and `spring-security-oauth2-resource-server` 6.5.11, all Runtime.
- Required fix:
  - MUST set `spring.security.version` to the lowest Spring Security release on Maven Central, at or above the identified 6.5.12, that moves all three artifacts outside all five owned ranges, read from `maven-metadata.xml` of `org/springframework/security/spring-security-bom` and confirmed with the scoped gate-3 check.
  - MUST keep `spring.ldap.version` 3.3.8 (`pom.xml:103`) and the Micrometer override (`pom.xml:93-97`) unchanged, and MUST reject every candidate whose POM requires Spring Framework 7 (`pom.xml:101-102`).
- Tests: no new test class; the regression evidence is the scoped gate-3 check over all three artifacts. A code change the upgrade forces MUST carry a regression test in the existing test module of the changed class.
- Estimated LOC: Production: 0–30; Test: 0–60; Configuration and build: 1–3; Documentation: 0–0
- Pass/fail: the validation command passes, the scoped gate-3 check over the 15 owned occurrences reports zero failures, and the collected Dependency-Check report lists none of the five IDs against any of the three upgraded artifacts.

---

CRITICAL Directive: Upgrade Testcontainers until its shaded HTTP components leave every owned range

- Finding: [DEP-12](SECURITY_FINDINGS.md#dep-12)
- CVE/CWE: CVE-2026-71290, CVE-2026-54399, CVE-2026-54428, CVE-2026-64607
- Severity: Critical 9.1
- Bucket: Dependency upgrade
- Files and classes: `pom.xml:168` (`testcontainers.version` 2.0.5), consumed by the `${testcontainers.version}` declarations at `pom.xml:275`, `:293`, `:305`, `:316`, `:328` and `:340`; `org.apache.httpcomponents.client5:httpclient5` 5.5.1 and `org.apache.httpcomponents.core5:httpcore5` 5.3.6 are shaded in `com.github.docker-java:docker-java-transport-zerodep` 3.7.1, which six ITEST modules reach in test scope.
- Required fix:
  - MUST set `testcontainers.version` to the lowest Testcontainers release on Maven Central whose `docker-java-transport-zerodep` embeds `httpclient5` and `httpcore5` outside all four ranges. The register names `httpclient5` 5.6.4 (CVE-2026-71290) and 5.6.3 (CVE-2026-64607); the containing release and the `httpcore5` fixed versions for CVE-2026-54399 and CVE-2026-54428 are not identified in scanner data.
  - MUST find that release by reading `maven-metadata.xml` of `org/testcontainers/testcontainers`, the `docker-java-transport-zerodep` version each candidate POM declares and the components that release embeds, and MUST confirm the choice with the scoped gate-3 check. The same `testcontainers` version then applies on every path, including the one under `testcontainers-keycloak` (`pom.xml:169`).
  - NEVER treat the root `httpcomponents.client5.version` and `httpcomponents.core5.version` pins (`pom.xml:107-108`) as a fix: they govern unshaded copies and NEVER replace shaded bytes. When no release clears every range, the directive fails its gate and NEVER records "no fix available".
- Tests: no new test class; the regression evidence is the scoped gate-3 check. The six ITEST modules stay outside the validation command and are reported as not run.
- Estimated LOC: Production: 0–30; Test: 0–60; Configuration and build: 1–3; Documentation: 0–0
- Pass/fail: the validation command passes, the scoped gate-3 check over the four owned shaded occurrences reports zero failures, and the collected Dependency-Check report lists none of the four IDs against the components shaded in the resolved `docker-java-transport-zerodep`.

---

CRITICAL Directive: Add a switched CSRF and SameSite policy to every OpenL Studio browser chain

- Finding: [SEC-04](SECURITY_FINDINGS.md#sec-04)
- CVE/CWE: CWE-352
- Severity: High 8.8
- Bucket: Default-changing fix
- Files and classes: `SingleSecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SingleSecurityConfig.java:27`), `FormBasedAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/FormBasedAuthenticationConfig.java:27-32`, `:42`), `SecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SecurityConfig.java:49`), `SamlSecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SamlSecurityConfig.java:55-66`, `:84-90`, `:107-134`), `OAuth2SecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/OAuth2SecurityConfig.java:54-60`, `:66-72`, `:90-95`, `:106-117`), `PatAuthenticationFilter` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/pat/filter/PatAuthenticationFilter.java:37`, `:68-69`, read only), `SpringInitializer` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/web/servlet/SpringInitializer.java:40`), `STUDIO/studio-ui/src/services/apiCall.ts:200-216`, `STUDIO/studio-ui/src/pages/LoginPage.tsx:24-30`, `STUDIO/studio-ui/src/routes/RedirectRoute.tsx:16-17`, `STUDIO/studio-ui/src/pages/403.tsx:14`, `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/CsrfSecurityFilterChainTest.java`, `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/webstudio/web/servlet/SpringInitializerTest.java`, `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/openapi/AbstractStudioOpenApiTest.java` (shared MockMvc base, carried here), `STUDIO/studio-ui/src/services/apiCall.test.ts`, `STUDIO/studio-ui/src/routes/RedirectRoute.test.tsx`, `STUDIO/studio-ui/src/pages/LoginPage.test.tsx`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - Issuance: at `security.csrf.enabled=true`, a `CsrfFilter` with a cookie token repository MUST issue a script-readable `XSRF-TOKEN` cookie with the same `SameSite` and `Secure` attributes as the session cookie, and MUST load the token on every response, so the cookie exists before the first write.
  - Placement: the chains are assembled by hand, so the filter MUST be added explicitly to every chain a browser reaches with an ambient credential: `SingleSecurityConfig.java:27`, `FormBasedAuthenticationConfig.java:28`, `FormBasedAuthenticationConfig.java:42`, `SecurityConfig.java:49`, `OAuth2SecurityConfig.java:106-117`, the SAML REST chain `SamlSecurityConfig.java:107-134`, the OIDC logout chain before its `LogoutFilter` (`OAuth2SecurityConfig.java:54-60`), and the SAML logout chain after `Saml2LogoutRequestFilter` and before `LogoutFilter("/", samlLogoutHandler)` (`SamlSecurityConfig.java:55-66`).
  - Logout: in the secure state every local logout MUST match POST only, because the token check passes GET as a safe method; in the default state the current logout matchers stay.
  - Exemptions: only a request already authenticated by a credential a browser never attaches by itself is exempt: a PAT in the `Authorization: Token` scheme (`PatAuthenticationFilter.java:37`, `:68-69`) or an OAuth2 bearer token on the OAuth2 REST chain (`OAuth2SecurityConfig.java:90-95`). HTTP Basic (`FormBasedAuthenticationConfig.java:27-32`) MUST NOT be exempt, because browsers cache Basic credentials and resend them on cross-site requests.
  - SSO messages: the SAML assertion consumer (`SamlSecurityConfig.java:84-90`) MUST carry no `CsrfFilter`, because SAML signature and `InResponseTo` checks protect it. In the SAML logout chain only an IdP logout message validated by `Saml2LogoutRequestFilter` (`SamlSecurityConfig.java:57`, `:64`) is handled without a token; every other request in that chain reaches the token check. OIDC has no exception: its logout chain is local logout and its callback is a GET (`OAuth2SecurityConfig.java:66-72`).
  - SameSite: `security.session-cookie.same-site` MUST be applied through `SessionCookieConfig` in `SpringInitializer` (`SpringInitializer.java:40`); `STUDIO/org.openl.rules.webstudio/webapp/WEB-INF/web.xml` stays unchanged. The empty default sets no attribute. `saml` mode uses `None` with `Secure`, because the IdP's POST binding is a cross-site POST that `Lax` strips of the session cookie holding the saved authentication request.
  - UI: `apiCall.ts:200-216` MUST send the `XSRF-TOKEN` cookie value as an `X-XSRF-TOKEN` header on every non-GET request, and `LoginPage.tsx:24-30` MUST send it on the login POST. Local logout (`RedirectRoute.tsx:16-17`, `403.tsx:14`) MUST become a form POST to `/logout` carrying the token as the `_csrf` field; both states accept that POST, so the UI change NEVER depends on the switch.
- Switch:
  - `security.csrf.enabled` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `false`; recommended secure value `true`.
  - `security.session-cookie.same-site` in the same file; default empty (attribute not set); recommended secure value `Lax` in `single`, `multi`, `ad` and `oauth2` modes and `None` with the `Secure` attribute in `saml` mode.
  - `WARN` owners: `SecurityConfig` logs one line while CSRF is disabled; `SpringInitializer` logs one line while SameSite is empty and one line while SameSite is `None` outside `saml` mode. Each line names SEC-04, its property and the secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping `security.csrf.enabled` refuses session and Basic writes without the token and stops GET logout. Script clients that use Basic read the token from the `XSRF-TOKEN` cookie any GET returns and send it as `X-XSRF-TOKEN`, or move to a PAT. `SameSite=None` requires HTTPS.
- Tests:
  - `CsrfSecurityFilterChainTest`, MockMvc on `AbstractStudioOpenApiTest`. Default: a state-changing request without a token is accepted, and a GET to `/logout` logs out. Secure: session and Basic writes without the token are refused with 403 and succeed with the `X-XSRF-TOKEN` header from the `XSRF-TOKEN` cookie; a PAT write without the token succeeds; a local logout POST without the token is refused, with the token it logs out, and a GET does not log out, in `multi`, `oauth2` and `saml` modes; a validated SAML IdP logout message built from a signed test fixture is processed without a token; the assertion endpoint is not CSRF-checked. Partially hardened: CSRF enabled with SameSite empty asserts the remaining `WARN`.
  - `SpringInitializerTest`: the session cookie carries no SameSite at the default and the mode's value at the secure setting; the empty value and `None` outside `saml` mode each log their `WARN`.
  - Vitest beside `apiCall.test.ts`: the header is sent on non-GET requests and not on GET; `RedirectRoute.test.tsx` and `LoginPage.test.tsx` prove that logout submits a POST with `_csrf` and that the login POST carries the header.
- Estimated LOC: Production: 220–360; Test: 700–1100; Configuration and build: 8–16; Documentation: 12–20
- Pass/fail: the validation command passes with the Vitest suites run, and `CsrfSecurityFilterChainTest`, `SpringInitializerTest`, `apiCall.test.ts`, `RedirectRoute.test.tsx` and `LoginPage.test.tsx` prove every default, secure and partially hardened state above; `docs/security/MIGRATION_NOTES.md` holds the SEC-04 entry.

---

CRITICAL Directive: Override brace-expansion to its first release outside every owned range

- Finding: [DEP-13](SECURITY_FINDINGS.md#dep-13)
- CVE/CWE: CVE-2026-102276 / GHSA-6j4f-fj2g-mc7p, CVE-2026-102278 / GHSA-qhr7-859c-m2p7, CVE-2026-102277 / GHSA-q2hr-2g5m-vwhr
- Severity: High 7.5
- Bucket: Dependency upgrade
- Files and classes: `STUDIO/studio-ui/package.json` (new `overrides` entry); `STUDIO/studio-ui/package-lock.json (generated)`. The only copy is `node_modules/brace-expansion` 5.0.9, a production dependency bundled into the OpenL Studio UI, whose parent `node_modules/minimatch` 10.2.6 declares `^5.0.8`.
- Required fix:
  - MUST add an `overrides` entry to `STUDIO/studio-ui/package.json` that sets `brace-expansion` to 5.0.12, the lowest release clearing all three ranges (fixed in 5.0.10, 5.0.11 and 5.0.12). When the scoped npm check still reports one of the three advisories, the target becomes the lowest later release from `npm view brace-expansion versions` that clears them.
  - The parent's declared range admits the target, so `minimatch` stays unchanged.
  - The lockfile MUST be regenerated only by the `npm install` execution of `STUDIO/studio-ui/pom.xml` inside the validation command, with npm 12.0.2; NEVER edit `package-lock.json` by hand.
- Tests: no new test; the Vitest suites run unchanged inside the validation command, and the regression evidence is the scoped npm check.
- Estimated LOC: Production: 0–0; Test: 0–0; Configuration and build: 4–10; Documentation: 0–0
- Pass/fail: the validation command passes, every `node_modules/brace-expansion` entry of the regenerated lockfile is at the selected release, and the scoped npm check reports none of GHSA-6j4f-fj2g-mc7p, GHSA-qhr7-859c-m2p7 and GHSA-q2hr-2g5m-vwhr.

---

CRITICAL Directive: Override http-cache-semantics to the lowest published release outside its advisory range

- Finding: [DEP-14](SECURITY_FINDINGS.md#dep-14)
- CVE/CWE: CVE-2026-93748 / GHSA-ch52-4w7c-c8xp
- Severity: High 7.5
- Bucket: Dependency upgrade
- Files and classes: `STUDIO/studio-ui/package.json` (new `overrides` entry); `STUDIO/studio-ui/package-lock.json (generated)`. The only copy is `node_modules/http-cache-semantics` 4.2.0, a development (Build) dependency whose parent `node_modules/make-fetch-happen` 15.0.6 declares `^4.1.1`.
- Required fix:
  - The fixed version is not identified in scanner data (2026-10-05), which is missing metadata, not evidence that no fix exists. The run MUST read `npm view http-cache-semantics versions` from `registry.npmjs.org` and MUST select the lowest release above 4.2.0 that the scoped npm check reports outside GHSA-ch52-4w7c-c8xp.
  - MUST add an `overrides` entry to `STUDIO/studio-ui/package.json` that sets `http-cache-semantics` to that release. When it lies outside the parent range `^4.1.1`, the override still applies and the Project Guide records the major-line change as a compatibility risk on the build-only `make-fetch-happen` path.
  - The lockfile MUST be regenerated only by the `npm install` execution inside the validation command. When no published release qualifies, the directive fails its gate and NEVER records "no fix available".
- Tests: no new test; the Vitest suites run unchanged inside the validation command, and the regression evidence is the scoped npm check.
- Estimated LOC: Production: 0–0; Test: 0–0; Configuration and build: 4–10; Documentation: 0–0
- Pass/fail: the validation command passes, every `node_modules/http-cache-semantics` entry of the regenerated lockfile is at the selected release, and the scoped npm check reports no GHSA-ch52-4w7c-c8xp.

---

CRITICAL Directive: Override the node-gyp copy of undici to its first fixed release

- Finding: [DEP-15](SECURITY_FINDINGS.md#dep-15)
- CVE/CWE: CVE-2026-19534 / GHSA-rfgv-xxqx-mfg5, CVE-2026-85024 / GHSA-3wwx-pv8p-q78v, CVE-2026-18540 / GHSA-r53p-7pc4-xj5r
- Severity: High 7.5
- Bucket: Dependency upgrade
- Files and classes: `STUDIO/studio-ui/package.json` (new nested `overrides` entry); `STUDIO/studio-ui/package-lock.json (generated)`. The affected copy is `node_modules/node-gyp/node_modules/undici` 6.28.0, a development (Build) dependency whose parent `node-gyp` 12.4.0 declares `^6.25.0`. The top-level `node_modules/undici` 8.10.2, required by `jsdom` as `^8.10.2`, is not affected.
- Required fix:
  - MUST add an `overrides` entry nested under `node-gyp` that sets its `undici` to 6.28.1, the first release that clears all three ranges; when the scoped npm check still reports one of the three advisories, the target becomes the lowest later 6.x release from `npm view undici versions` that clears them.
  - NEVER override `undici` at the top level: the `node_modules/undici` 8.10.2 entry MUST stay unchanged.
  - The lockfile MUST be regenerated only by the `npm install` execution inside the validation command.
- Tests: no new test; the Vitest suites run unchanged inside the validation command, and the regression evidence is the scoped npm check.
- Estimated LOC: Production: 0–0; Test: 0–0; Configuration and build: 4–10; Documentation: 0–0
- Pass/fail: the validation command passes, `node_modules/node-gyp/node_modules/undici` in the regenerated lockfile is at the selected release, `node_modules/undici` stays at 8.10.2, and the scoped npm check reports none of GHSA-rfgv-xxqx-mfg5, GHSA-3wwx-pv8p-q78v and GHSA-r53p-7pc4-xj5r.

---

CRITICAL Directive: Add a switch that stops external group names from granting ADMIN

- Finding: [SEC-10](SECURITY_FINDINGS.md#sec-10)
- CVE/CWE: CWE-269
- Severity: High 7.5
- Bucket: Default-changing fix
- Files and classes: `GetUserPrivileges.mapAuthorities` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/GetUserPrivileges.java:49-56`), `Privileges` (`STUDIO/org.openl.security/src/org/openl/rules/security/Privileges.java:11-18`), `AdminPrivilege` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/AdminPrivilege.java:32`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/GetUserPrivilegesTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `security.external-groups.allow-admin-mapping=false`, `GetUserPrivileges` MUST NOT grant `ADMIN` from an OpenL group matched by an external authority name (`GetUserPrivileges.java:52`) or from a raw external `ADMIN` authority kept as is (`GetUserPrivileges.java:54`).
  - Explicit local grants stored for the user and the non-administrative privileges of matched groups MUST stay unchanged.
  - At the default (`true`) the mapping MUST behave exactly as today.
- Switch:
  - `security.external-groups.allow-admin-mapping` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `true`; recommended secure value `false`.
  - `WARN` owner: `GetUserPrivileges` logs one line while the value is `true` in `ad`, `saml` or `oauth2` mode, naming SEC-10, the property and `false`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value removes `ADMIN` from users who receive it only through an IdP group named like an OpenL group; administrators are then granted `ADMIN` explicitly in OpenL Studio.
- Tests: `GetUserPrivilegesTest`. Default: an external `Administrators` authority grants `ADMIN`. Secure: the same authority does not grant `ADMIN`, a raw external `ADMIN` authority does not grant it, and explicit local grants and other group permissions remain. The `WARN` is asserted at the default in `ad` mode and absent at the secure value.
- Estimated LOC: Production: 30–55; Test: 90–150; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `GetUserPrivilegesTest` proves both states and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-10 entry.

---

CRITICAL Directive: Add switched multipart parser limits to the OpenL Studio dispatcher servlet

- Finding: [SEC-26](SECURITY_FINDINGS.md#sec-26)
- CVE/CWE: CWE-770
- Severity: High 7.5
- Bucket: Default-changing fix
- Files and classes: `SpringInitializer.registerDispatcherServlet` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/web/servlet/SpringInitializer.java:153-158`), `ApiExceptionControllerAdvice.handleMultipartException` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/common/ApiExceptionControllerAdvice.java:130-137`, read only), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/webstudio/web/servlet/SpringInitializerTest.java` and `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/common/ApiExceptionControllerAdviceTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - `registerDispatcherServlet` MUST build its `MultipartConfigElement` from `upload.max-file-size` and `upload.max-request-size` instead of the literal `-1L` values, keeping the file-size threshold unchanged.
  - The servlet container enforces these limits, so the fix NEVER adds an application-level size check.
- Switch:
  - `upload.max-file-size` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `-1` (bytes; negative means unlimited); recommended secure value `104857600`.
  - `upload.max-request-size` in the same file; default `-1`; recommended secure value `209715200`.
  - `WARN` owner: `SpringInitializer` logs one line while the file limit is negative and one line while the request limit is negative, each naming SEC-26, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the limits refuses uploads above 100 MiB per file or 200 MiB per request; operators who import larger projects raise the values and align their ingress limits.
- Tests: server-free. `SpringInitializerTest` captures the registered `MultipartConfigElement` with a mocked `ServletContext`, as `SpringInitializerTest.java:22-40` does. Default: the element carries `-1` and `-1`. Secure: it carries `104857600` and `209715200`. Partially hardened: one negative value logs its `WARN`. `ApiExceptionControllerAdviceTest` proves that a container part-limit failure maps to the upload-size error.
- Estimated LOC: Production: 35–60; Test: 100–180; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, and the tests prove the registered values in each state, the `WARN` lines and the error mapping. Container-level refusal of an oversized upload is listed in the Project Guide as not verified in-JVM.

---

CRITICAL Directive: Add a switched row cap to the XLSX run-result export

- Finding: [SEC-27](SECURITY_FINDINGS.md#sec-27)
- CVE/CWE: CWE-770
- Severity: High 7.5
- Bucket: Default-changing fix
- Files and classes: `ProjectsRunController` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/projects/rest/controller/ProjectsRunController.java:63`, export at `:183-188`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/projects/rest/controller/ProjectsRunControllerTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At a non-negative `test.run.export.max-rows`, the XLSX export MUST refuse a result with more rows than the cap with an explicit error whose message names `test.run.export.max-rows`, before it builds the workbook, and MUST export a result at the cap.
  - At the default (`-1`) the export MUST behave exactly as today's `Integer.MAX_VALUE` call.
- Switch:
  - `test.run.export.max-rows` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`, beside `test.run.thread.count` (`:66`); default `-1` (negative means unlimited); recommended secure value `100000`.
  - `WARN` owner: `ProjectsRunController` bean construction logs one line while the value is negative, naming SEC-27, the property and `100000`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value refuses exports above 100000 rows; users export filtered runs or raise the cap.
- Tests: `ProjectsRunControllerTest`. Default: a result above 100000 rows is exported in full. Secure: the same export is refused with the property-naming error, and a result at the cap exports. The `WARN` is asserted at the default and absent at the secure value.
- Estimated LOC: Production: 25–45; Test: 80–140; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `ProjectsRunControllerTest` proves both states and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-27 entry.

---

CRITICAL Directive: Add a switch that refuses non-HTTPS remote JWKS locations

- Finding: [SEC-33](SECURITY_FINDINGS.md#sec-33)
- CVE/CWE: CWE-319
- Severity: High 7.5
- Bucket: Default-changing fix
- Files and classes: the `JWTValidator` constructor (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/spring/JWTValidator.java:44`, JWKS resolution at `:55-65`), `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`; test `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/spring/JWTValidatorTest.java` (created by SEC-01; created here when absent); `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `ruleservice.authentication.allow-insecure-jwks=false`, the constructor MUST fail with an explicit error naming `ruleservice.authentication.jwks` and the property when the JWKS location is neither `https:` nor `file:`, before it opens the location.
  - `https:` and `file:` locations MUST keep their current resolvers, and the default (`true`) MUST behave exactly as today.
- Switch:
  - `ruleservice.authentication.allow-insecure-jwks` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`, beside `ruleservice.authentication.enabled` (`:59`); default `true`; recommended secure value `false`.
  - `WARN` owner: the `JWTValidator` constructor logs one line while authentication is enabled, the value is `true` and the `ruleservice.authentication.jwks` location is neither `https:` nor `file:`, naming SEC-33, the property and `false`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value refuses startup with a plain-HTTP JWKS location; operators move the key set to HTTPS or to a local file.
- Tests: `JWTValidatorTest`. Default: an `http:` location passes the scheme check and logs the `WARN`. Secure: an `http:` location fails construction with the explicit error, while `https:` and `file:` locations pass the scheme check. The test checks the scheme policy before any resolver opens the location and NEVER opens a remote location.
- Estimated LOC: Production: 25–45; Test: 80–140; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `JWTValidatorTest` proves both states and the `WARN` without opening a remote location, and `docs/security/MIGRATION_NOTES.md` holds the SEC-33 entry.

---

CRITICAL Directive: Add switched minimum and maximum lengths for internal passwords

- Finding: [SEC-08](SECURITY_FINDINGS.md#sec-08)
- CVE/CWE: CWE-521
- Severity: High 7.4
- Bucket: Default-changing fix
- Files and classes: `InternalPasswordConstraintValidator` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/rest/validation/InternalPasswordConstraintValidator.java:25-36`), `MultiSecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/MultiSecurityConfig.java`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; test `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/rest/validation/UsersValidatorTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - `InternalPasswordConstraintValidator` MUST read `security.password.min-length` and `security.password.max-length` instead of the literal 25, refusing a non-blank password shorter than the minimum or longer than the maximum with the existing size messages.
  - The blank-password handling MUST stay as today: multi mode still refuses a blank password when internal users can be created.
  - This directive NEVER adds login lockout; SEC-13 owns it.
- Switch:
  - `security.password.min-length` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`, beside `security.password.encoder` (`:5`); default `0`; recommended secure value `12`.
  - `security.password.max-length` in the same place; default `25`; recommended secure value `64`.
  - `WARN` owner: `MultiSecurityConfig` logs one line while the minimum is below 12 and one line while the maximum is below 64, each naming SEC-08, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the minimum refuses new passwords shorter than 12 characters; existing passwords keep working until they are changed.
- Tests: `UsersValidatorTest`. Default: a 0-character and a 26-character password follow today's mode-specific rules. Secure: a password shorter than 12 is refused, 26 to 64 characters are accepted, and above 64 is refused. Partially hardened: the minimum at 12 with the maximum at 25 asserts the remaining `WARN`.
- Estimated LOC: Production: 35–60; Test: 100–180; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, `UsersValidatorTest` proves the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-08 entry.

---

CRITICAL Directive: Add switched failed-login counting and timed lockout to OpenL Studio

- Finding: [SEC-13](SECURITY_FINDINGS.md#sec-13)
- CVE/CWE: CWE-307
- Severity: High 7.4
- Bucket: Default-changing fix
- Files and classes: `FormBasedAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/FormBasedAuthenticationConfig.java:24-49`), `CommonAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/CommonAuthenticationConfig.java`), new `STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/FailedLoginTracker.java`, `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/FailedLoginTrackerTest.java` and `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/LoginLockoutTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - In `multi` and `ad` modes with `security.login.max-failed-attempts` above 0, `FailedLoginTracker` MUST count consecutive failed logins per user name thread-safely and MUST refuse that user's login for `security.login.lockout-seconds` once the count reaches the limit; a successful login resets the count, and the lock ends when the period expires.
  - At the default (`0`) no failure locks an account, exactly as today. The Git credential back-off (`STUDIO/org.openl.rules.repository.git/resources/openl-default.properties:14-19`) stays unchanged, and SEC-08 stays a separate directive.
- Switch:
  - `security.login.max-failed-attempts` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `0` (0 disables lockout); recommended secure value `5`.
  - `security.login.lockout-seconds` in the same file; default `300`; recommended secure value `300`.
  - `WARN` owner: `FormBasedAuthenticationConfig` in `multi` or `ad` mode logs one line while the attempts value is `0` and one line while the lockout is `0` with attempts above `0`, each naming SEC-13, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the attempts value locks an account for 300 seconds after 5 consecutive failures; API rate limiting stays a proxy action (section 6 of `SECURITY_FINDINGS.md`).
- Tests: `FailedLoginTrackerTest` and `LoginLockoutTest`. Default: repeated failed logins never lock the account. Secure: the account is refused after 5 failures until the lockout ends, then a correct login succeeds, and concurrent failed attempts are counted exactly. Partially hardened: attempts above 0 with lockout 0 asserts its `WARN`.
- Estimated LOC: Production: 90–160; Test: 240–400; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, `FailedLoginTrackerTest` and `LoginLockoutTest` prove the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-13 entry.

---

CRITICAL Directive: Add a switched JWT signature algorithm allow-list to OpenL Rule Services

- Finding: [SEC-34](SECURITY_FINDINGS.md#sec-34)
- CVE/CWE: CWE-327
- Severity: High 7.4
- Bucket: Default-changing fix
- Files and classes: the `JWTValidator` constructor (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/spring/JWTValidator.java:44`, algorithm constraint at `:68-75`), `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`; test `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/spring/JWTValidatorTest.java` (created by SEC-01; created here when absent); `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - A non-empty `ruleservice.authentication.algorithms` MUST replace `AlgorithmConstraints.DISALLOW_NONE` (`JWTValidator.java:74`) with a permit-list constraint holding exactly the listed algorithms.
  - The empty default MUST keep `DISALLOW_NONE`, and the expiry, issuer, audience and signature checks (`JWTValidator.java:68-75`) MUST stay unchanged in both states.
- Switch:
  - `ruleservice.authentication.algorithms` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`, beside `ruleservice.authentication.enabled` (`:59`); default empty (every algorithm except `none`); recommended secure value `RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512`.
  - `WARN` owner: the `JWTValidator` constructor logs one line while authentication is enabled and the list is empty, naming SEC-34, the property and the secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value refuses tokens signed with an algorithm outside the list, including HMAC algorithms; issuers sign with a listed algorithm.
- Tests: `JWTValidatorTest`. Default: a token signed with any supported algorithm other than `none` and compatible with the configured key is accepted. Secure: a token signed with an algorithm outside the list is refused, while listed algorithms and the issuer, audience and expiry checks keep working. The `WARN` is asserted at the default with authentication enabled.
- Estimated LOC: Production: 30–55; Test: 90–160; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `JWTValidatorTest` proves both states and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-34 entry.

---

CRITICAL Directive: Add authenticated ENC2 secret encryption beside unchanged ENC decryption

- Finding: [SEC-07](SECURITY_FINDINGS.md#sec-07)
- CVE/CWE: CWE-327
- Severity: High 7.1
- Bucket: Default-changing fix
- Files and classes: `PassCoder` (`DEV/org.openl.spring/src/org/openl/spring/env/PassCoder.java:23-24` zero IV, `:71-76` truncated SHA-1 key), `DynamicPropertySource` (`DEV/org.openl.spring/src/org/openl/spring/env/DynamicPropertySource.java:138-220`: `save` encrypts only `*password` keys at `:146`, `decode` returns an empty string on failure at `:214-216`), new `DEV/org.openl.spring/src/org/openl/spring/env/SecretReencryptor.java`, `DEV/org.openl.spring/resources/openl-default.properties:12-35`; tests `DEV/org.openl.spring/test/org/openl/spring/env/PassCoderTest.java`, `DEV/org.openl.spring/test/org/openl/spring/env/RefPropertySourceTest.java` and `DEV/org.openl.spring/test/org/openl/spring/env/SecretReencryptorTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - This directive stands alone and NEVER groups with another finding.
  - MUST add `ENC2(...)` encryption with authenticated encryption (AES-GCM), a random IV per value and a salted key derivation from `secret.key`, carrying the salt and IV inside the encoded value.
  - At `secret.encryption.format=ENC2`, `DynamicPropertySource.save` MUST write `ENC2(...)` values; at the default it writes `ENC(...)` exactly as today.
  - `secret.encryption.name-suffixes` MUST select which property names `save` encrypts; the default `password` reproduces today's `endsWith("password")` check.
  - A failed `ENC2(...)` decryption, including a tampered value or a wrong key, MUST raise an explicit error naming the property key and NEVER return an empty string.
  - `ENC(...)` decryption, including its current empty-string result on failure, MUST stay unchanged; one `WARN` naming the property key on an `ENC` decryption failure is the only addition.
  - `SecretReencryptor` in `DEV/org.openl.spring` MUST rewrite the `ENC(...)` values of a settings file as `ENC2(...)` values and leave every other line unchanged.
- Switch:
  - `secret.encryption.format` in `DEV/org.openl.spring/resources/openl-default.properties`, beside the `secret.*` keys (`:12-38`); default `ENC`; recommended secure value `ENC2`.
  - `secret.encryption.name-suffixes` in the same place; default `password`; recommended secure value `password,secret,secret-key,access-key,account-key,client-secret,local-key`.
  - `WARN` owner: `DynamicPropertySource` logs one startup line while the format is `ENC` and one line while the suffix list omits any suffix of the secure value, which leaves those secrets in plain text; each names SEC-07, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the format writes `ENC2(...)` values that earlier releases cannot read, so every node is upgraded before the flip and `SecretReencryptor` converts existing settings files; `ENC(...)` values keep decrypting.
- Tests: `PassCoderTest`, `RefPropertySourceTest` and `SecretReencryptorTest`, in the `PassCoderTest` style. Default: `ENC(...)` values round-trip unchanged and a failed `ENC` decryption keeps its current result and logs the `WARN`. Secure: `ENC2(...)` values round-trip; a tampered value or a wrong key raises the explicit error naming the property; the utility converts `ENC` values to `ENC2`; `ENC(...)` values still decrypt. Partially hardened: format `ENC2` with suffixes `password` asserts the remaining `WARN`.
- Estimated LOC: Production: 180–300; Test: 450–700; Configuration and build: 8–16; Documentation: 12–20
- Pass/fail: the validation command passes, the three tests prove the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-07 entry.

---

CRITICAL Directive: Add switched separate SAML encryption keys and a shorter certificate validity

- Finding: [SEC-23](SECURITY_FINDINGS.md#sec-23)
- CVE/CWE: CWE-323
- Severity: High 7.0
- Bucket: Default-changing fix
- Files and classes: `Migrator` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/Migrator.java:103-114`), `KeyPairCertUtils` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/web/install/KeyPairCertUtils.java:39-52`), `SAMLAuthenticationSettings` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/web/admin/security/SAMLAuthenticationSettings.java`), `LazyInMemoryRelyingPartyRegistrationRepository` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/saml/LazyInMemoryRelyingPartyRegistrationRepository.java:43-58`), `SamlSecurityConfig`, `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/webstudio/MigratorSamlKeysTest.java`, `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/webstudio/web/install/KeyPairCertUtilsTest.java` and `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/saml/SamlKeyRegistrationTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `security.saml.separate-encryption-key=true`, key generation MUST create a second key pair and certificate for decryption beside the signing pair when none exists, and `LazyInMemoryRelyingPartyRegistrationRepository` MUST build the decryption credential from it.
  - `KeyPairCertUtils` MUST take the certificate validity from `security.saml.certificate-validity-days` instead of the fixed ten years.
  - Existing generated keys and certificates MUST be kept and NEVER regenerated by this change.
  - At the defaults one key pair serves both purposes with a 3650-day certificate, exactly as today.
- Switch:
  - `security.saml.separate-encryption-key` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`, beside the `security.saml.*` keys (`:231`); default `false`; recommended secure value `true`.
  - `security.saml.certificate-validity-days` in the same place; default `3650`; recommended secure value `730`.
  - `WARN` owner: `SamlSecurityConfig` in `saml` mode logs one line while one key serves both purposes and one line while the validity exceeds 730 days, each naming SEC-23, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the key switch publishes distinct signing and encryption certificates in the SP metadata, so each IdP imports the new metadata; a 730-day certificate needs rotation every two years.
- Tests: `MigratorSamlKeysTest`, `KeyPairCertUtilsTest` and `SamlKeyRegistrationTest`. Default: one generated key pair serves both purposes and its certificate is valid for 3650 days. Secure: two key pairs are generated, each certificate is valid for 730 days, and existing keys are kept. Partially hardened: the separate key on with validity 3650 asserts the remaining `WARN`, and the metadata lists both certificates.
- Estimated LOC: Production: 130–220; Test: 320–540; Configuration and build: 14–24; Documentation: 10–18
- Pass/fail: the validation command passes, the three tests prove the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-23 entry.

---

CRITICAL Directive: Rotate the session ID on SAML and OIDC login

- Finding: [SEC-06](SECURITY_FINDINGS.md#sec-06)
- CVE/CWE: CWE-384
- Severity: Medium 6.8
- Bucket: Code fix
- Files and classes: the `sessionAuthenticationStrategy` bean of `CommonAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/CommonAuthenticationConfig.java:65-68`), used by the SAML login filter (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SamlSecurityConfig.java:224`) and the OIDC login filter (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/OAuth2SecurityConfig.java:188`); test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/CommonAuthenticationConfigTest.java`.
- Required fix:
  - The bean MUST compose session-ID rotation (`ChangeSessionIdAuthenticationStrategy`) followed by the existing `RegisterSessionAuthenticationStrategy`, so every SAML and OIDC login changes the session ID and registers the new ID in the `SessionRegistry`.
  - Session attributes, including saved SSO state, MUST survive the rotation, and the online-user marker that reads the registry MUST keep working.
- Tests: `CommonAuthenticationConfigTest` with a mocked request holding an existing session: after authentication the session ID differs, the attributes are kept, and the registry holds the new ID and not the old one.
- Estimated LOC: Production: 12–24; Test: 50–100; Configuration and build: 0–0; Documentation: 0–0
- Pass/fail: the validation command passes, and `CommonAuthenticationConfigTest` proves the identifier change, the retained attributes and the registry continuity.

---

CRITICAL Directive: Add a switched maximum lifetime for personal access tokens

- Finding: [SEC-09](SECURITY_FINDINGS.md#sec-09)
- CVE/CWE: CWE-613
- Severity: Medium 6.8
- Bucket: Default-changing fix
- Files and classes: `PatGeneratorServiceImpl.generateToken` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/pat/service/PatGeneratorServiceImpl.java:61-86`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/pat/service/PatGeneratorServiceImplTest.java` and `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/openapi/PatLifetimeOpenApiTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At a positive `security.pat.max-lifetime-days`, token creation MUST refuse a missing `expiresAt` and an `expiresAt` beyond that many days after creation, and the REST API MUST answer such a request with a stable 400 response.
  - At the default (`0`) an absent expiry stays accepted, exactly as today, and the existing past-expiry check (`PatGeneratorServiceImpl.java:66-68`) stays unchanged.
  - Existing tokens keep their stored expiry.
- Switch:
  - `security.pat.max-lifetime-days` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `0` (0 means expiry optional); recommended secure value `90`.
  - `WARN` owner: `PatGeneratorServiceImpl` logs one line while the value is `0` and one line while it is above 365, each naming SEC-09, the property and `90`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value refuses new tokens without an expiry or with an expiry beyond 90 days; automation renews its tokens before they expire.
- Tests: `PatGeneratorServiceImplTest` and `PatLifetimeOpenApiTest`. Default: a PAT without `expiresAt` is created. Secure: a PAT without `expiresAt`, or with an expiry beyond 90 days, is refused with 400, and one within 90 days is created. The `WARN` is asserted at `0` and above 365.
- Estimated LOC: Production: 40–70; Test: 110–200; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, the two tests prove both states and the `WARN` lines, and `docs/security/MIGRATION_NOTES.md` holds the SEC-09 entry.

---

CRITICAL Directive: Add a switch that refuses plaintext LDAP in AD mode

- Finding: [SEC-17](SECURITY_FINDINGS.md#sec-17)
- CVE/CWE: CWE-319
- Severity: Medium 6.8
- Bucket: Default-changing fix
- Files and classes: `AdSecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/AdSecurityConfig.java`, which reads `security.ad.server-url`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties:274`; test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/AdSecurityConfigTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `security.ad.allow-plaintext-ldap=false`, AD-mode startup MUST fail with an explicit error naming `security.ad.server-url` and the property whenever the server URL starts with `ldap://`.
  - `ldaps://` URLs MUST keep working, and the default (`true`) MUST behave exactly as today.
  - The default `security.ad.server-url` value stays unchanged, because it is an existing default.
- Switch:
  - `security.ad.allow-plaintext-ldap` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`, beside `security.ad.server-url` (`:274`); default `true`; recommended secure value `false`.
  - `WARN` owner: `AdSecurityConfig` logs one line while `security.ad.server-url` starts with `ldap://` and the value is `true`, naming SEC-17, the property and `false`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value refuses AD-mode startup with an `ldap://` URL; operators serve LDAP over `ldaps://` with a trusted certificate.
- Tests: `AdSecurityConfigTest`, with no remote connection. Default: an `ldap://` URL starts AD mode and logs the `WARN`. Secure: an `ldap://` URL fails startup with the explicit error, and a mocked `ldaps://` configuration succeeds.
- Estimated LOC: Production: 30–50; Test: 80–140; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `AdSecurityConfigTest` proves both states and the `WARN` without a remote connection, and `docs/security/MIGRATION_NOTES.md` holds the SEC-17 entry.

---

CRITICAL Directive: Add switched security headers and a Content Security Policy to every OpenL Studio chain

- Finding: [SEC-05](SECURITY_FINDINGS.md#sec-05)
- CVE/CWE: CWE-1021
- Severity: Medium 6.5
- Bucket: Default-changing fix
- Files and classes: `SecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SecurityConfig.java:30-58`, headers disabled at `:56`), `SamlSecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SamlSecurityConfig.java:53-134`), `OAuth2SecurityConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/OAuth2SecurityConfig.java:52-117`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/SecurityHeadersTest.java`; `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/openapi/AbstractStudioOpenApiTest.java` (shared, counted in SEC-04); `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `security.http-headers.all-chains.enabled=true`, the static chain MUST stop disabling headers (`SecurityConfig.java:56`), and the SAML and OIDC chains MUST write Spring Security's default security headers, through a header writer added explicitly where a chain is assembled by hand.
  - At a non-empty `security.http-headers.content-security-policy`, every OpenL Studio chain MUST send a `Content-Security-Policy` header with that value.
  - At the defaults the SAML, OIDC and static chains MUST send no security headers and no chain sends a policy, exactly as today, so current embedding keeps working.
- Switch:
  - `security.http-headers.all-chains.enabled` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `false`; recommended secure value `true`.
  - `security.http-headers.content-security-policy` in the same file; default empty; recommended secure value `default-src 'self'; frame-ancestors 'self'`.
  - `WARN` owner: `SecurityConfig` logs one line while headers are off on any chain and one line while the policy is empty, each naming SEC-05, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the values adds frame and content-type headers and the policy to SSO and static responses, which blocks framing by other origins and loading of off-site scripts; integrations that embed OpenL Studio extend the policy.
- Tests: `SecurityHeadersTest`, MockMvc. Default: SAML, OIDC and static chain responses carry no security headers. Secure: those responses carry the default headers and the policy. Partially hardened: headers on with an empty policy asserts the remaining `WARN`.
- Estimated LOC: Production: 60–100; Test: 160–260; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, `SecurityHeadersTest` proves the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-05 entry.

---

CRITICAL Directive: Add a switched capacity to the Kafka worker queue with consumer back-pressure

- Finding: [SEC-31](SECURITY_FINDINGS.md#sec-31)
- CVE/CWE: CWE-770
- Severity: Medium 5.9
- Bucket: Default-changing fix
- Files and classes: the static executor of `KafkaService` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/kafka/publish/KafkaService.java:56-61`), `KafkaRuleServicePublisher` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/kafka/publish/KafkaRuleServicePublisher.java`), `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`; test `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/kafka/publish/KafkaWorkerQueueTest.java`, which carries the Kafka startup fixture SEC-32 reuses; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - The worker queue MUST come from `ruleservice.kafka.worker-queue-capacity`: a negative value keeps today's unbounded `LinkedBlockingQueue`, and a positive value bounds the queue.
  - When a bounded queue is full, a new submission MUST NOT be queued: the consumer applies back-pressure until capacity frees and NEVER drops or acknowledges the waiting record.
  - Executor start, restart and shutdown MUST stay correct when several Kafka-published services run.
- Switch:
  - `ruleservice.kafka.worker-queue-capacity` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`, beside the `ruleservice.kafka.*` keys (`:26-27`); default `-1` (negative means unbounded); recommended secure value `10000`.
  - `WARN` owner: `KafkaRuleServicePublisher` logs one line at service startup while the value is negative, naming SEC-31, the property and `10000`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value slows consumption once 10000 records wait, instead of growing memory without limit.
- Tests: `KafkaWorkerQueueTest`, with mocked consumers and no broker. Default: submissions beyond 10000 queue without limit. Secure: submissions beyond the capacity are not queued and the consumer applies back-pressure; restart, shutdown and several service instances behave correctly. The `WARN` is asserted at the default.
- Estimated LOC: Production: 80–140; Test: 220–380; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `KafkaWorkerQueueTest` proves both states, the lifecycle cases and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-31 entry.

---

CRITICAL Directive: Add a switched allow-list for Kafka reply and dead-letter topic headers

- Finding: [SEC-32](SECURITY_FINDINGS.md#sec-32)
- CVE/CWE: CWE-610
- Severity: Medium 5.9
- Bucket: Default-changing fix
- Files and classes: `KafkaService.getOutTopic` and `KafkaService.getDltTopic` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/kafka/publish/KafkaService.java:152-170`), `KafkaRuleServicePublisher`, `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`; test `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/kafka/publish/KafkaTopicRoutingTest.java`; `KafkaWorkerQueueTest` (shared startup fixture, counted in SEC-31); `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - A reply-topic or dead-letter-topic header MUST be honoured only when its topic is in `ruleservice.kafka.allowed-reply-topics`. The value `*` honours every header, exactly as today; an empty list permits only the configured output and dead-letter topics.
  - A refused header MUST be ignored, and the reply MUST go to the configured output or dead-letter topic.
- Switch:
  - `ruleservice.kafka.allowed-reply-topics` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`, beside the `ruleservice.kafka.*` keys (`:26-27`); default `*`; recommended secure value an explicit topic list, where empty means the configured output and dead-letter topics only.
  - `WARN` owner: `KafkaRuleServicePublisher` logs one line when a Kafka-published service starts while the value is `*`, naming SEC-32, the property and the secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value stops replies to topics outside the list; clients that name their own reply topics get them listed.
- Tests: `KafkaTopicRoutingTest`, with mocked records and no broker. Default: a record whose reply-topic header names an unlisted topic is answered on that topic. Secure: that header is ignored and the reply goes to the configured topic, while a listed topic still works. The `WARN` is asserted at the default.
- Estimated LOC: Production: 45–80; Test: 130–220; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `KafkaTopicRoutingTest` proves both states and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-32 entry.

---

CRITICAL Directive: Add switched trusted-proxy lists for forwarded headers in both applications

- Finding: [SEC-16](SECURITY_FINDINGS.md#sec-16)
- CVE/CWE: CWE-348
- Severity: Medium 5.4
- Bucket: Default-changing fix
- Files and classes: the `ForwardedFilter` declaration of `de.qaware.xff.filter.ForwardedHeaderFilter` from `org.openl:x-forwarded-filter` 2.0 (`STUDIO/org.openl.rules.webstudio/webapp/WEB-INF/web.xml:33-44`, `pom.xml:482-490`), `SpringInitializer` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/web/servlet/SpringInitializer.java`), new `STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/web/servlet/TrustedForwardedHeaderFilter.java`, `RuleServicesFilter` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/servlet/RuleServicesFilter.java:69-70`, `:99`), both `openl-default.properties` files named below; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/webstudio/web/servlet/TrustedForwardedHeaderFilterTest.java` and `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/servlet/RuleServicesFilterTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - OpenL Studio: `TrustedForwardedHeaderFilter` MUST take the place of the `ForwardedFilter` declaration at the same position in the filter order and delegate to the existing filter, with the same `xForwardedPrefixStrategy` `PREPEND`, only when the original peer address is in `security.forwarded-headers.trusted-proxies`; any other request passes through unwrapped.
  - OpenL Rule Services: `RuleServicesFilter.doFilter` (`:99`) MUST apply its `ForwardedHeaderFilter` only when the original peer address is in `ruleservice.forwarded-headers.trusted-proxies`, and process every other request unwrapped.
  - Both checks MUST read the peer address before any forwarded header is applied. `*` trusts every peer, exactly as today.
- Switch:
  - `security.forwarded-headers.trusted-proxies` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `*`; recommended secure value the proxy addresses, for example `127.0.0.1,::1`.
  - `ruleservice.forwarded-headers.trusted-proxies` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`; default `*`; recommended secure value the proxy addresses, for example `127.0.0.1,::1`.
  - `WARN` owners: `SpringInitializer` (OpenL Studio) and `RuleServicesFilter` initialization (OpenL Rule Services) each log one line while their value is `*`, naming SEC-16, the property and the secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value ignores forwarded headers from unlisted peers, so generated links and client addresses behind an unlisted proxy fall back to the direct connection; operators list every proxy address.
- Tests: `TrustedForwardedHeaderFilterTest` and `RuleServicesFilterTest`, with mocked requests. Default: `X-Forwarded-*` headers from any remote address are applied. Secure: they are applied only from listed proxies and ignored from other peers. Partially hardened: one application hardened with the other at `*` asserts the remaining `WARN`.
- Estimated LOC: Production: 120–220; Test: 280–480; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, both tests prove the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-16 entry.

---

CRITICAL Directive: Refuse off-site targets in the post-login redirect

- Finding: [SEC-29](SECURITY_FINDINGS.md#sec-29)
- CVE/CWE: CWE-601
- Severity: Medium 5.4
- Bucket: Code fix
- Files and classes: the `authenticationSuccessHandler` bean of `CommonAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/CommonAuthenticationConfig.java:71-75`, target parameter `from` at `:74`); test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/CommonAuthenticationConfigTest.java`.
- Required fix:
  - The success handler MUST follow the `from` value only when it normalizes to a same-origin relative path: a single leading `/`, no scheme, no authority and no backslash.
  - Any other value MUST fall back to the saved request or to the default target `/`, and same-site relative targets MUST keep working.
- Tests: `CommonAuthenticationConfigTest`. A same-site relative `from` value redirects there; an absolute URL naming another host, a scheme-relative value and a backslash-prefixed value each fall back to the default target; the saved-request fallback keeps working.
- Estimated LOC: Production: 30–50; Test: 90–150; Configuration and build: 0–0; Documentation: 0–0
- Pass/fail: the validation command passes, and `CommonAuthenticationConfigTest` proves that every off-site form is refused while same-site targets and the saved-request fallback keep working.

---

CRITICAL Directive: Override ip-address to its first release outside every owned range

- Finding: [DEP-16](SECURITY_FINDINGS.md#dep-16)
- CVE/CWE: CVE-2026-101910 / GHSA-2vr4-cq9g-pvrc, CVE-2026-101911 / GHSA-h3mg-xc3c-68pw, CVE-2026-101912 / GHSA-j6r3-76f7-8jcv, CVE-2026-101913 / GHSA-rpw4-54j3-4h4q
- Severity: Medium 5.3
- Bucket: Dependency upgrade
- Files and classes: `STUDIO/studio-ui/package.json` (new `overrides` entry); `STUDIO/studio-ui/package-lock.json (generated)`. The only copy is `node_modules/ip-address` 10.4.0, a development (Build) dependency whose parent `node_modules/socks` 2.8.9 declares `^10.1.1`.
- Required fix:
  - MUST add an `overrides` entry to `STUDIO/studio-ui/package.json` that sets `ip-address` to 10.7.1, the lowest release clearing all four ranges (fixed in 10.5.1 and 10.7.1). When the scoped npm check still reports one of the four advisories, the target becomes the lowest later release from `npm view ip-address versions` that clears them.
  - The parent's declared range admits the target, so `socks` stays unchanged.
  - The lockfile MUST be regenerated only by the `npm install` execution inside the validation command.
- Tests: no new test; the Vitest suites run unchanged inside the validation command, and the regression evidence is the scoped npm check.
- Estimated LOC: Production: 0–0; Test: 0–0; Configuration and build: 4–10; Documentation: 0–0
- Pass/fail: the validation command passes, every `node_modules/ip-address` entry of the regenerated lockfile is at the selected release, and the scoped npm check reports none of the four GHSA IDs; no owned row reaches CVSS 7.0, so this check is the whole gate.

---

CRITICAL Directive: Add switches that require authentication for the system-information endpoints

- Finding: [SEC-11](SECURITY_FINDINGS.md#sec-11)
- CVE/CWE: CWE-200
- Severity: Medium 5.3
- Bucket: Default-changing fix
- Files and classes: `SysInfoController` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/common/SysInfoController.java:26-100`, `sys.json` and `http.json` under `/rest/public/info/`), the static chain matcher `/rest/public/**` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/SecurityConfig.java:43`), `AdminRestController` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/admin/AdminRestController.java:39-140`, `/admin/info/*` and `/admin/config/application.properties`), `RuleServicesFilter.skipAuthorization` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/servlet/RuleServicesFilter.java:204-209`), the `/admin/` exemption of `JWTValidator.authorize` (`WSFrontend/org.openl.rules.ruleservice.ws/src/org/openl/rules/ruleservice/spring/JWTValidator.java:83-85`), both `openl-default.properties` files named below; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/openapi/SystemInfoSecurityTest.java` and `WSFrontend/org.openl.rules.ruleservice.ws/test/org/openl/rules/ruleservice/servlet/RuleServicesFilterTest.java`; `AbstractStudioOpenApiTest` (shared, counted in SEC-04); `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - OpenL Studio: at `security.public-system-info.enabled=false`, `/rest/public/info/sys.json` and `/rest/public/info/http.json` MUST leave the static chain and require authentication; their paths stay unchanged.
  - OpenL Rule Services: at `ruleservice.admin.public-info.enabled=false` with authentication enabled, `skipAuthorization` MUST stop exempting `/admin/info/` and `/admin/config/`, and `JWTValidator.authorize` MUST NOT exempt them either, so the token check applies; `/admin/healthcheck/` stays public in both states.
  - At the defaults (`true`) both applications MUST behave exactly as today.
- Switch:
  - `security.public-system-info.enabled` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `true`; recommended secure value `false`.
  - `ruleservice.admin.public-info.enabled` in `WSFrontend/org.openl.rules.ruleservice.ws/resources/openl-default.properties`, beside `ruleservice.authentication.enabled` (`:59`); default `true`; recommended secure value `false`.
  - `WARN` owners: `SecurityConfig` logs one line while the Studio value is `true` outside `single` mode; `RuleServicesFilter` initialization logs one line while the Rule Services value is `true` with `ruleservice.authentication.enabled=true`. Each names SEC-11, its property and `false`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the values makes monitoring that reads these endpoints authenticate; health checks stay anonymous.
- Tests: `SystemInfoSecurityTest` (MockMvc) and `RuleServicesFilterTest`. Default: `sys.json` and `http.json` (OpenL Studio) and `/admin/info/*` (OpenL Rule Services) answer anonymously. Secure: they require authentication, while `/admin/healthcheck/readiness` stays public. Partially hardened: one application hardened with the other at its default asserts the remaining `WARN`.
- Estimated LOC: Production: 65–110; Test: 180–300; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, both tests prove the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-11 entry.

---

CRITICAL Directive: Add a switched maximum of concurrent sessions per user

- Finding: [SEC-30](SECURITY_FINDINGS.md#sec-30)
- CVE/CWE: CWE-770
- Severity: Medium 5.3
- Bucket: Default-changing fix
- Files and classes: the session management of `FormBasedAuthenticationConfig.defaultFilterChain` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/FormBasedAuthenticationConfig.java:45-47`, `maximumSessions(-1)`), `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/FormBasedAuthenticationConfigTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - `maximumSessions` MUST take its value from `security.max-sessions-per-user`; a negative value keeps unlimited sessions, exactly as today.
  - At a positive value a new login beyond the limit MUST expire the oldest session of that user and NEVER refuse the new login, and the `SessionRegistry` MUST stay consistent.
- Switch:
  - `security.max-sessions-per-user` in `STUDIO/org.openl.rules.webstudio/resources/openl-default.properties`; default `-1` (negative means unlimited); recommended secure value `10`.
  - `WARN` owner: `FormBasedAuthenticationConfig` logs one line while the value is negative, naming SEC-30, the property and `10`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value ends the oldest session of a user who signs in an eleventh time.
- Tests: `FormBasedAuthenticationConfigTest`. Default: an eleventh concurrent session is kept. Secure: the eleventh login expires the oldest session and the registry stays consistent. The `WARN` is asserted at the default.
- Estimated LOC: Production: 25–45; Test: 80–140; Configuration and build: 4–8; Documentation: 8–15
- Pass/fail: the validation command passes, `FormBasedAuthenticationConfigTest` proves both states and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-30 entry.

---

CRITICAL Directive: Add switched payload storage and retention to the store-log database

- Finding: [SEC-12](SECURITY_FINDINGS.md#sec-12)
- CVE/CWE: CWE-359
- Severity: Medium 4.7
- Bucket: Default-changing fix
- Files and classes: `DBStoreLogDataService` (`WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/src/org/openl/rules/ruleservice/storelogdata/db/DBStoreLogDataService.java`), `EntityManagerOperations` (`WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/src/org/openl/rules/ruleservice/storelogdata/db/EntityManagerOperations.java`), the `@Lob` `request` and `response` columns of `DefaultEntity` (`WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/src/org/openl/rules/ruleservice/storelogdata/db/DefaultEntity.java:42-52`), `WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/resources/openl-default.properties:1`; tests `WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/test/org/openl/rules/ruleservice/storelogdata/db/EntityManagerOperationsTest.java` and `WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/test/org/openl/rules/ruleservice/storelogdata/db/DBStoreLogDataServiceTest.java`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `ruleservice.store.logs.db.store-payloads=false`, every stored record MUST leave its request-body and response-body columns empty, while every other column stays as today.
  - At a positive `ruleservice.store.logs.db.retention-days`, a scheduled purge MUST delete records older than that many days.
  - At the defaults bodies are stored and nothing is purged, exactly as today.
- Switch:
  - `ruleservice.store.logs.db.store-payloads` in `WSFrontend/org.openl.rules.ruleservice.ws.storelogdata.db/resources/openl-default.properties`, beside `ruleservice.store.logs.db.enabled` (`:1`); default `true`; recommended secure value `false`.
  - `ruleservice.store.logs.db.retention-days` in the same place; default `0` (0 means no purge); recommended secure value `30`.
  - `WARN` owner: `DBStoreLogDataService`, while store-log is enabled, logs one line while payloads are stored and one line while retention is `0`, each naming SEC-12, its property and its secure value.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the values stops storing request and response bodies and deletes records after 30 days; reports that read the bodies or old records change.
- Tests: `EntityManagerOperationsTest` and `DBStoreLogDataServiceTest`. Default: request and response bodies are stored and no record is purged. Secure: bodies are not stored, and records older than the retention period are purged while newer ones stay. Partially hardened: payloads off with retention `0` asserts the remaining `WARN`.
- Estimated LOC: Production: 100–180; Test: 250–420; Configuration and build: 8–16; Documentation: 8–15
- Pass/fail: the validation command passes, both tests prove the default, secure and partially hardened states, and `docs/security/MIGRATION_NOTES.md` holds the SEC-12 entry.

---

CRITICAL Directive: Add a switch that requests S3 server-side encryption on every write

- Finding: [SEC-22](SECURITY_FINDINGS.md#sec-22)
- CVE/CWE: CWE-311
- Severity: Medium 4.7
- Bucket: Default-changing fix
- Files and classes: `S3Repository` (`STUDIO/org.openl.rules.repository.aws/src/org/openl/rules/repository/aws/S3Repository.java:276-287` file writes, `:523-527` modification marker), `STUDIO/org.openl.rules.repository.aws/resources/openl-default.properties:16-19`, `STUDIO/org.openl.rules.repository.aws/pom.xml` (test dependencies); new test root `STUDIO/org.openl.rules.repository.aws/test` with `STUDIO/org.openl.rules.repository.aws/test/org/openl/rules/repository/aws/S3RepositoryEncryptionTest.java`, styled after `STUDIO/org.openl.rules.repository/test`; `docs/security/MIGRATION_NOTES.md`.
- Required fix:
  - At `repo-aws-s3.sse-request.enabled=true` with a non-blank `repo-aws-s3.sse-algorithm`, every `putObject` request, for saved files and for the modification marker, MUST request server-side encryption with that algorithm (`AES256` or `aws:kms`).
  - The existing `sseAlgorithm` metadata entry stays in both states, and at the default (`false`) requests carry no server-side encryption, exactly as today.
  - The module has no test source root, so the directive MUST add `STUDIO/org.openl.rules.repository.aws/test` and the JUnit and Mockito test dependencies to the module POM.
- Switch:
  - `repo-aws-s3.sse-request.enabled` in `STUDIO/org.openl.rules.repository.aws/resources/openl-default.properties`, beside `repo-aws-s3.sse-algorithm` (`:16-19`); default `false`; recommended secure value `true`.
  - `WARN` owner: `S3Repository` initialization logs one line while `repo-aws-s3.sse-algorithm` is set and requests carry no server-side encryption, naming SEC-22, the property and `true`.
  - `docs/security/MIGRATION_NOTES.md` entry: flipping the value makes S3 encrypt new objects; with `aws:kms` the repository credentials also need permission to use the key.
- Tests: `S3RepositoryEncryptionTest` with a mocked S3 client and no remote call. Default: with `sse-algorithm` `AES256`, the `putObject` requests for a file and for the modification marker carry the algorithm only as metadata. Secure: the same requests ask for server-side encryption with `AES256`. The `WARN` is asserted at the default.
- Estimated LOC: Production: 40–70; Test: 140–240; Configuration and build: 12–24; Documentation: 8–15
- Pass/fail: the validation command passes and runs the new test root, `S3RepositoryEncryptionTest` proves both states and the `WARN`, and `docs/security/MIGRATION_NOTES.md` holds the SEC-22 entry.

---

CRITICAL Directive: Erase password credentials after authentication while keeping SAML logout state

- Finding: [SEC-28](SECURITY_FINDINGS.md#sec-28)
- CVE/CWE: CWE-316
- Severity: Medium 4.7
- Bucket: Code fix
- Files and classes: the `authenticationManager` bean of `CommonAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/CommonAuthenticationConfig.java:29-48`, erasure disabled at `:47` with the SAML logout reason at `:46`), `OpenLAuthenticationProviderWrapper` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/ad/OpenLAuthenticationProviderWrapper.java:12-24`, read only); test `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/CommonAuthenticationConfigTest.java`.
- Required fix:
  - After a successful `multi` or `ad` authentication, the password credential of the returned authentication MUST be erased.
  - The state SAML global logout needs MUST be kept, so the SAML authentication NEVER loses it; OAuth2 handling stays unchanged, because it stores no password.
- Tests: `CommonAuthenticationConfigTest` with mocked authentication objects: a `multi` or `ad` authentication returns no password credential, a SAML authentication keeps the state its logout needs, and an OAuth2 authentication is unchanged.
- Estimated LOC: Production: 25–45; Test: 80–140; Configuration and build: 0–0; Documentation: 0–0
- Pass/fail: the validation command passes, and `CommonAuthenticationConfigTest` proves the per-mode credential handling.

---

CRITICAL Directive: Log secret-free security events at authentication, PAT, ACL and membership boundaries

- Finding: [SEC-15](SECURITY_FINDINGS.md#sec-15)
- CVE/CWE: CWE-778
- Severity: Medium 4.3
- Bucket: Code fix
- Files and classes: `CommonAuthenticationConfig` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/CommonAuthenticationConfig.java`), `PatGeneratorServiceImpl` (`STUDIO/org.openl.rules.webstudio/src/org/openl/studio/security/pat/service/PatGeneratorServiceImpl.java`), `BulkAclOverwriteServiceImpl` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/rest/acl/service/BulkAclOverwriteServiceImpl.java`), `GroupManagementService` and `UserManagementService` (`STUDIO/org.openl.rules.webstudio/src/org/openl/rules/webstudio/service/`); evidence `LastLoginRecorder.java:23-31`, `STUDIO/org.openl.security.acl/src/org/openl/security/acl/config/EnabledAclConfiguration.java:63`, `STUDIO/org.openl.security.standalone/resources/db/flyway/common/V13.4__Merge_privileges_into_roles.sql:7-12`; tests `STUDIO/org.openl.rules.webstudio/test/org/openl/studio/security/SecurityEventAuditTest.java` and `STUDIO/org.openl.rules.webstudio/test/org/openl/rules/rest/acl/service/SecurityEventAuditTest.java`.
- Required fix:
  - MUST write one structured event through one dedicated logger for each failed login, access denial, PAT creation and deletion, ACL change, and user or group membership change, naming the acting user, the subject and the outcome.
  - Events MUST NEVER contain a password, token secret, session identifier or request body.
  - Successful-login recording (`LastLoginRecorder.java:23-31`) and every existing behavior stay unchanged.
- Tests: the two `SecurityEventAuditTest` classes capture the logger and prove that each event above is written with its fields and that no secret value appears in any event.
- Estimated LOC: Production: 100–180; Test: 180–300; Configuration and build: 0–0; Documentation: 0–0
- Pass/fail: the validation command passes, and both tests prove every event and the absence of secrets.

---

CRITICAL Directive: Evict ACL cache entries after commit on every revocation path

- Finding: [SEC-25](SECURITY_FINDINGS.md#sec-25)
- CVE/CWE: CWE-613
- Severity: Medium 4.2
- Bucket: Code fix
- Files and classes: `SimpleRepositoryAclServiceImpl` (`STUDIO/org.openl.security.acl/src/org/openl/security/acl/repository/SimpleRepositoryAclServiceImpl.java:232-253` and `:279-330` revocation paths, existing `evictCacheOnCommit` at `:79-95`), the two-minute ACL cache (`STUDIO/org.openl.rules.webstudio/resources/cache2k.xml:17-18`, read only); test `STUDIO/org.openl.security.acl/test/org/openl/security/acl/repository/AclRevocationCacheTest.java`.
- Required fix:
  - Every `removePermissions` overload MUST evict the affected identity, and its affected descendants, through the existing `evictCacheOnCommit`, in addition to the eviction before the write, so a read during the uncommitted transaction cannot leave a stale grant cached.
  - The cache configuration stays unchanged.
- Tests: `AclRevocationCacheTest` with an active transaction synchronization: a cache read between the revocation and the commit repopulates the entry, and after completion the entry is gone, for every revocation overload.
- Estimated LOC: Production: 40–80; Test: 100–200; Configuration and build: 0–0; Documentation: 0–0
- Pass/fail: the validation command passes, and `AclRevocationCacheTest` proves post-commit eviction on every revocation overload.

---
