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

  <!-- V1: opening a file-repository project leaves out the files that links place outside the project folder -->
* **Opening a project from a file design repository no longer copies files that links place outside the project
  folder.** In a `repo-file` design repository, a file that a symbolic link places outside the project folder —
  outside the repository, or into another project — is left out of the user's workspace when the project is opened,
  and its content is not read. The opened project does not list it, find it in a search or serve it (`404`), as the
  closed project already did not. Links that stay inside the project folder keep working and are copied as their
  content. A project folder that is itself a link, or that sits under a link below the repository root, opens
  empty. Links in the configured repository root's own path are trusted. Git and the other non-file repositories
  are unaffected. On each such open, the server logs a WARN that names the project and the number of files left
  out: "… file(s) of the project '…' are not copied to the workspace, because links place them outside the project
  folder." Saving the project afterwards writes the working copy back, so the link entries that were left out are
  removed from the project in the design repository; the files they pointed to are not touched. Before upgrading,
  replace a link that a project needs for shared content with a regular copy of the file inside the project.

  <!-- V1: an upload that overwrites a project whose folder holds a link out of it is refused -->
* **An upload that overwrites a project is refused when the project folder holds a link that leads out of it.** In
  a `repo-file` design repository, and in the working tree of a `repo-git` design repository, uploading files or a
  template over an existing project answers `400` with `openl.error.400.file.path.invalid.message` when any entry
  of the existing project folder is a symbolic link that resolves outside that folder — outside the repository,
  into another project, or to nothing. Nothing is written, no commit is made, and the uploaded files are discarded.
  Links that stay inside the project folder do not stop the upload. Before upgrading, replace such a link with a
  regular copy of its content inside the project, or remove it, so the project can be overwritten.

## Testing Recommendations

After upgrading, verify in a non-production environment:

1. Every project that carries a `groovy/` folder compiles and deploys.
2. A service published from such a project answers as it did before.
3. Heap headroom, if the maximum heap is set close to the previous usage.
4. A client that calls the OpenL Studio API answers on `/rest`, and its WebSocket connects to `/rest/ws`.
   <!-- V1: a file-repository project that holds links opens with only the files of its own folder -->
5. A project of a file design repository that holds symbolic links opens with the files of its own folder.
