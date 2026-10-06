---
title: "OpenL Tablets 6.5.0 Migration Notes"
---

Upgrading to OpenL Tablets 6.5.0 requires no database changes and no Java version change. Two changes need
attention. Groovy moves from `4.0.33` to `6.0.0`, skipping the whole 5.x line, so a project that carries Groovy
sources needs a source-compatibility check; every deployment runs the new Groovy runtime, so the administrator
notes below apply even where no project carries Groovy sources. Separately, the `/web` prefix of the OpenL Studio
API is removed, and `/rest` is the only prefix left — which affects everyone who calls that API from outside the
browser.

## Rules Authors

* **The OpenL Studio screens need nothing from you for the API prefix change.** They call the new address
  on their own.

* **A source-compatibility check is needed only for a project with a `groovy/` folder.** Rules in Excel are not
  compiled by Groovy, so they need no re-save and no re-compile for the language changes below.

* **A static member can no longer be called through a parameterized type.** Groovy 6 rejects what Groovy 4 accepted,
  applying the rule Java has always had:

  ```groovy
  Literal<Node> x = Literal<Node>.of(true)   // no longer compiles
  Literal<Node> x = Literal.of(true)         // write this instead
  ```

  Groovy reports `Cannot refer to a static member of a generic type through a parameterization`. Removing the type
  argument from the call is the whole fix — the variable keeps its declared type and behavior does not change.

* **Recognize the symptom.** A Groovy class that fails to compile surfaces as a missing type rather than as a
  compilation error. The module reports `Cannot load type: <fully qualified class name>`, and a service built from
  that project fails to deploy. Compiling the project's Groovy sources directly against Groovy 6 shows the real
  message.

> [!Note]
> The rule above is the change OpenL's own projects had to adapt to. Groovy 6 carries further changes over the 4.x
> line, and the 5.x line is skipped entirely, so consult the Groovy release notes before upgrading a project that
> leans on less common language features.

## Developers

* **Replace `/web/` with `/rest/` in every client.** The path after the prefix is unchanged, so
  `/web/projects/{id}/files` becomes `/rest/projects/{id}/files`. There is no redirect and no compatibility
  period.
* **A check for a `2xx` is not enough while you migrate.** A `GET /web/...` no longer fails — the address falls
  through to the page the application is drawn on, so the response is `200` with an HTML body. A client that
  only tests the status code will parse that page as JSON. A non-GET answers `405`. Search your clients for
  the literal `/web` rather than relying on error handling to surface the change.
* **No client needs new credentials.** `/rest` accepts everything `/web` did and more: the session cookie in
  every mode, a Personal Access Token in all multi-user modes, HTTP Basic in `ad` and `multi`, and a Bearer
  token in `oauth2`.
* **The WebSocket endpoint is `{context}/rest/ws`, and it is authenticated.** `/web/ws` is gone. It used to
  admit an anonymous handshake, which is what made the public notification topic readable without signing in;
  that is no longer the case. Connect with the session cookie the browser already holds, or send an
  `Authorization` header on the handshake, as `/rest/ws` has always accepted.
* **In `oauth2` mode an unauthenticated API call now answers `401` with `WWW-Authenticate: Bearer`** instead
  of a bare `401`. A `Bearer` challenge raises no browser credential dialog, so a browser client is
  unaffected; a scripted client that inspects the header should expect it.
* **SAML and OIDC logins rotate the session ID.** A client must use the `JSESSIONID` set by the login callback,
  not the one it received before logging in.
  <!-- V5: session ID rotation on SAML and OIDC login -->
* **The OWASP and Trivy scans now fail on high-severity findings.** `mvn -Powasp` fails for any dependency finding
  with a CVSS score of 7.0 or higher (`failBuildOnCVSS` 7.0 in the `owasp` profile). The nightly or manually started
  Trivy workflow fails on fixable `HIGH` or `CRITICAL` findings in the scanned image, and still produces its JSON and
  HTML reports. Neither gate runs on merge or publish. The root `pom.xml` adds `tomcat.version` (10.1.60), which
  overrides the `tomcat-embed-core`, `tomcat-embed-el` and `tomcat-embed-websocket` 10.1.55 that Spring Boot 3.5.16
  manages, for CVE-2026-53404, CVE-2026-53434, CVE-2026-55276, CVE-2026-59083, CVE-2026-59084, CVE-2026-65182,
  CVE-2026-65183, CVE-2026-65637, CVE-2026-65905, CVE-2026-65927, CVE-2026-66422, CVE-2026-68525, CVE-2026-68569,
  CVE-2026-68763, CVE-2026-75973, CVE-2026-76183, CVE-2026-77762, CVE-2026-77791, CVE-2026-78383, CVE-2026-78437,
  CVE-2026-79677, CVE-2026-86248, CVE-2026-86350 and CVE-2026-87022. Remove the override once Spring Boot manages a
  fixed Tomcat version.
  <!-- V13: OWASP and Trivy scanning gates -->

## Administrators

* **Groovy 6 requires Java 17 or later**, which OpenL Tablets already exceeds — it requires Java 21. No JDK change
  is needed.

* **Groovy 6 occupies more heap at rest than Groovy 4.** A deployment whose maximum heap is tuned close to its
  previous usage should re-measure before upgrading. For scale: the memory-constrained suite in OpenL's own build
  runs under a 61 MB cap and needed 2 MB more to pass on Groovy 6.

* **`groovy.use.classvalue` is now a mode, not a flag.** Groovy 6 reads `true` (the default) and `soft` as keeping
  the class-metadata cache backed by `java.lang.ClassValue`; any other value selects the map-based cache. Setting it
  to `false` keeps `ClassValue` out of the cache, which is what avoids the classloader pinning behind the metaspace
  leak of GROOVY-12142; the `soft` mode added by GROOVY-12281 keeps `ClassValue` but lets its entries be reclaimed.
  Groovy 5 ignored the property altogether, so a deployment that set it while passing through 5.x on its own should
  confirm the value again.

* **Repoint anything that routes or allows `/web`.** Check reverse-proxy location blocks, ingress rules, API
  gateway routes, WAF path rules and the `cors.allowed.origins` consumers for `/web`, and change them to
  `/rest`. A proxy that forwards `/web/ws` for the WebSocket must forward `/rest/ws` instead.

* **An e-mail verification link deployed under a context path containing `web` is fixed.** With the default
  `/webstudio` context path the link previously lost that path and did not resolve. No action is required
  beyond upgrading; a link sent by an earlier version stays broken.

* **Rule Services `/admin/` endpoints need a JWT once `ruleservice.authentication.enabled=true`.** Only
  `/admin/healthcheck/`, `/admin/info/` and `/admin/config/` stay open. `/admin/deploy`, `/admin/services`,
  `/admin/ui/info`, `/admin/swagger-ui.json` and any OpenAPI document under `/admin/` answer `401` without an
  `Authorization` header and `403` with an invalid token, so scripts must send `Authorization: Bearer ${JWT_TOKEN}`.
  Service OpenAPI documents outside `/admin/` stay public. The built-in Rule Services web page cannot attach a token,
  so its service list, service errors, `MANIFEST.MF` and deployment upload, download and delete stop working while
  authentication is on, and its Swagger UI page cannot list the services. Nothing changes with authentication off,
  the default.
  <!-- V2: Rule Services /admin/ paths require a JWT -->

* **Workspace folders, project files, new projects and uploaded archives are kept inside their own folders.** A
  user's workspace folder under `user.workspace.home` must be a real folder of its own: one that is a symbolic link
  into another user's folder or out of the workspace home, or a dangling link, is refused, and so is the folder of a
  user whose login name holds a character that OpenL Studio does not allow in file names, such as `'`, `:` or `%`,
  starts with a space, ends with a dot or a space, or is a reserved name such as `CON`, `NUL` or `COM1` in upper
  case. OpenL Studio does not open the workspace of such a user. In user workspaces and in a `repo-file` design
  repository, the project files API no longer follows a symbolic link that leads out of the project folder, outside
  the repository or into another project: listings and searches leave the entry out, and reading, updating, copying,
  moving, exporting or writing through it answers `400` with `openl.error.400.file.path.invalid.message`. In a
  `repo-file` design repository, creating or copying a project answers the same `400` when the new project folder
  would be reached through such a link. Creating a project from uploaded files and copying a project also answer that
  `400` for a project name or path holding a control character, which was previously removed silently. A project
  archive with an entry name that is not a valid relative path, such as one with a `..` segment or a leading `/`, is
  refused before anything is written. Copying a project answers that `400` as well when a file of the project being
  copied leads out of its folder through a link, in a `repo-file` design repository or, for an opened project, in the
  user's workspace.

  In a `repo-file` design repository, a file that a symbolic link places outside the project folder — outside the
  repository, or into another project — is left out of the user's workspace when the project is opened, and its
  content is not read. The opened project does not list it, find it in a search or serve it (`404`), as the closed
  project already did not. Links that stay inside the project folder keep working and are copied as their content. A
  project folder that is itself a link, or that sits under a link below the repository root, opens empty. Links in
  the configured repository root's own path are trusted. On each such open, the server logs a WARN that names the
  project and the number of files left out: "… file(s) of the project '…' are not copied to the workspace, because
  links place them outside the project folder." Saving the project afterwards writes the working copy back, so the
  link entries that were left out are removed from the project in the design repository; the files they pointed to
  are not touched.

  In a `repo-file` design repository, and in the working tree of a `repo-git` design repository, uploading files or a
  template over an existing project answers that `400` when any entry of the existing project folder is a symbolic
  link that resolves outside that folder — outside the repository, into another project, or to nothing. Nothing is
  written, no commit is made, and the uploaded files are discarded. There, an archive uploaded over an existing
  project answers that `400` when one of its entries would be written through such a link. Links that stay inside the
  project folder do not stop an upload. A `repo-git` design repository writes uploads through that working tree, so
  uploading files, a template or an archive to it also answers that `400` when the project folder would be reached
  through a link there. The files API on its closed projects and on the repository itself, and a project copied into
  it, get the name checks only; opening its projects, and reading the source when one of its closed projects is
  copied, are unchanged. JDBC, S3 and Azure Blob repositories keep no local folder, so no link check applies to them:
  they get the name checks only. Before upgrading, replace such links with regular folders or with copies of their
  content inside the project, or remove them.
  <!-- V1: path containment on the workspace, file, project and upload surfaces (A, B, C, D) -->

* **The OpenL Studio session cookie is now `SameSite=Lax`.** SAML login keeps working, but the identity provider's
  response must reach OpenL Studio within 5 minutes of the login request, and after a cross-site SAML callback the
  user lands on `/` instead of the page first requested. An IdP-initiated SAML logout that the browser delivers as a
  cross-site HTTP-POST arrives without the Studio session cookie, which `SameSite=Lax` withholds, so it can no longer
  end the Studio session. Configure the HTTP-Redirect binding for front-channel logout. CSRF tokens stay disabled.
  <!-- V3: SameSite=Lax session cookie -->

* **SAML, OIDC and static-resource responses now carry the default security headers.** They send what the `multi`,
  `ad` and `single` modes already sent: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Cache-Control: no-cache, no-store, max-age=0, must-revalidate` with `Pragma: no-cache` and `Expires: 0`,
  `X-XSS-Protection: 0`, and `Strict-Transport-Security` on HTTPS requests. OpenL Studio therefore cannot be shown
  in a frame in the `saml` and `oauth2` modes either. Static assets that set no cache headers of their own are no
  longer cached. No Content-Security-Policy is added.
  <!-- V4: default security headers on SAML, OIDC and static chains -->

* **Local passwords must have at least 12 characters and at most 72 bytes in UTF-8.** The rule replaces the
  25-character maximum and applies when a local user is created, when an administrator changes a user's password and
  when users change their own password in their profile. A violation answers `400` with
  `openl.constraints.password.min-length.message` or `openl.constraints.password.max-bytes.message`. Existing
  passwords and their hashes are untouched, so a shorter password keeps working until it is next changed.
  <!-- V7: local password length policy -->

* **New personal access tokens always expire.** A token created without `expiresAt`, including through the "No
  expiration" option of the token dialog, expires after `security.pat.default-expiration-days` (default `90`). An
  expiration date more than `security.pat.max-expiration-days` (default `365`) ahead answers `400` with
  `openl.error.400.pat.expires-at.max.message`. Both properties take a whole number of days written as an integer,
  such as `90`, not a decimal or a duration such as `P90D`. Each must be positive, and the default must not exceed
  the maximum. A value that breaks these rules stops OpenL Studio at startup. Tokens created before the upgrade
  without an expiry keep working and never expire.
  <!-- V8: PAT default and maximum expiration -->

* **Five failed logins lock a login name for 15 minutes in the `multi` and `ad` modes.** Five consecutive failed form
  or HTTP Basic logins within 15 minutes lock that name, compared case-insensitively, for 15 minutes. During the lock
  even the correct password gets the ordinary failed-login response, and a successful login resets the count.
  Unknown names are counted and locked exactly like existing ones. The counters live in the memory of each OpenL
  Studio instance and are cleared on restart. SSO, Bearer and personal access token logins are not counted. Anyone
  who knows an account name can lock it on purpose, and Active Directory name variants such as `user`,
  `DOMAIN\user` and `user@domain` are counted separately.
  <!-- V9: failed-login lockout -->

* **Stored secrets are encrypted with AES-256-GCM.** When the settings are saved, each setting whose name ends in
  `password`, `secret` or `token`, except `secret.key`, is written as `ENC(v2:...)`: AES-256-GCM under a
  PBKDF2-derived key, with a random salt and nonce per value. Legacy `ENC(...)` and plain-text values of such
  settings are still read and are rewritten in the new format on the next save. With the default blank
  `secret.key`, the first such save creates the instance key file `${openl.home.shared}/.openl-secret-key`: back it
  up and move it together with the settings file, or set `secret.key` before the first save. Once their key file is
  lost, the values read as empty and an ERROR is logged. OpenL Rule Services versions older than 6.5.0 cannot read
  `ENC(v2:...)` values. Settings ending in `secret-key`, `account-key` or `local-key`, such as
  `security.saml.local-key`, stay plain text.
  <!-- V6: AES-256-GCM encryption of stored secrets -->

* **`/rest/public/info/sys.json` and `/rest/public/info/http.json` now require authentication.** In the `multi`,
  `ad`, `saml` and `oauth2` modes they answer `401` to a request that is not authenticated, as the rest of `/rest`
  does; in `single` mode they are unchanged. `openl.json`, `build.json` and `/rest/settings` stay public. Monitoring
  that polls the two endpoints must authenticate.
  <!-- V10: sys.json and http.json require authentication -->

* **Security events are logged to `org.openl.security.audit`.** The logger writes one line per authentication
  success or failure, lockout, personal access token creation and revocation, and committed ACL change. Each line
  starts with `event`, `outcome`, `user` and `ip`, followed by the event's details: `method`, the token's public ID
  (`pat`), or the ACL change count, kinds and object types (`changes`, `kinds`, `objectTypes`). No line contains a
  password, token, token name, ACL object identifier or SID. Successes are logged at INFO, failures and lockouts at
  WARN, through the existing appenders; route the logger to an appender of its own to keep the trail apart. `ip` is
  the remote address the servlet container reports, so behind a reverse proxy it is the proxy's address unless the
  container takes the client address from a forwarded header, as Tomcat's `RemoteIpValve` or Jetty's
  `ForwardedRequestCustomizer` do. Each request authenticated by HTTP Basic, a Bearer token or a personal access
  token adds a line.
  <!-- V11: security audit logger -->

* **A WARN flags an identity-provider group that grants `ADMIN` by its name.** At each AD, SAML, OIDC or
  bearer-token login, OpenL Studio logs a WARN when an external group name matches an OpenL group that holds
  `ADMIN`, because the user gains administrator rights through that name match alone. The mapping is unchanged, and
  requests authenticated by a personal access token do not warn. If the grant is unintended, rename one of the
  groups.
  <!-- V12: warning for IdP groups that grant ADMIN by name -->

* **A WARN at startup flags a deployment without authentication.** OpenL Studio logs it when it runs with
  `user.mode=single`, and OpenL Rule Services when `ruleservice.authentication.enabled` is `false`, blank or not
  set. The defaults are unchanged.
  <!-- V14: startup warning when authentication is off -->

## Testing Recommendations

After upgrading, verify in a non-production environment:

1. Every project that carries a `groovy/` folder compiles and deploys.
2. A service published from such a project answers as it did before.
3. Heap headroom, if the maximum heap is set close to the previous usage.
4. A client that calls the OpenL Studio API answers on `/rest`, and its WebSocket connects to `/rest/ws`.
   <!-- V1: a file-repository project that holds links opens with only the files of its own folder -->
5. A project of a file design repository that holds symbolic links opens with the files of its own folder.
