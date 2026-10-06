# V10: system information needs a session

`sys.json` and `http.json` describe the host, the JVM and the request, so since V10 they require authentication in
every mode that has a login: `SecurityConfig.staticResourcesFilterChain` no longer matches them, and the mode's
`/rest/**` chain decides. In this `multi` suite, `010` and `011` answer `401` without credentials or a cookie,
`020` signs in through the login form, and `030` answers `200` with nothing but the session cookie that sign-in set.
`http.json` gets the same session-only check from `WebStudioTest`, not from a fixture of this folder (see below).
`040` logs out, and `050` and `051` show `sys.json` and `http.json` answering `401` again. `060` shows that
`openl.json` stays public, because the login screen reads it before anyone has signed in.

These steps live in a folder of their own because the suite resets cookies at a first-level folder boundary, so
`010` and `011` are truly anonymous. `030` carries no `Authorization` header, which leaves the form-login session as
its only credential; at the suite root it could ride another folder's session and prove nothing.

This folder is a deliberate exception to "Cookie/Session Handling" in `ITEST/AGENTS.md`, which keeps the login form
to the `003`–`008` sequence at the root of `itest.studio/multi/test-resources`. The V10 remediation plan requires a
second place, because "`200` with a session" can only be shown with a session that a real sign-in created. The
folder does not sign a scenario in.

`030` and `060` carry no `.resp`: the framework then expects `200` and ignores the body, and on a mismatch it prints
the response and saves its body under `target/responses/`. These two endpoints allow that, because they echo no
request header or cookie. `051` asks for `http.json` only after `040` has ended the session, and its `.resp` expects
the `401`, which echoes nothing. `http.json` echoes the request's headers and cookies, so its session-only check is
not a fixture of this folder: `WebStudioTest` signs in with `020`'s form itself and sends
`test-resources-security-V10-sysinfo/031-http-json-session.req` with only that session cookie, through a Java client
that discards the body and asserts `200`, naming only the status. The session ID joins the generated secrets that
the captured-output and saved-response scans search for. The password in `020` is `${ADMIN_PASSWORD}`, which
`WebStudioTest` supplies at runtime; no credential is written in this folder.

In `single` mode there is no login and every visitor holds `ADMIN`, so both endpoints stay `200` there, as the
`simple` suite's `info/sys.json` and `info/http.json` fixtures keep asserting.
