# V10: system information needs a session

`sys.json` and `http.json` describe the host, the JVM and the request, so since V10 they require authentication in
every mode that has a login: `SecurityConfig.staticResourcesFilterChain` no longer matches them, and the mode's
`/rest/**` chain decides. In this `multi` suite, `010` and `011` answer `401` without credentials or a cookie,
`020` signs in through the login form, and `030` and `031` answer `200` with nothing but the session cookie that
sign-in set. `040` logs out and `050` shows `sys.json` answering `401` again. `060` shows that `openl.json` stays
public, because the login screen reads it before anyone has signed in.

These steps live in a folder of their own because the suite resets cookies at a first-level folder boundary, so
`010` and `011` are truly anonymous. `030` and `031` carry no `Authorization` header, which leaves the form-login
session as their only credential; at the suite root they could ride another folder's session and prove nothing.

This folder is a deliberate exception to "Cookie/Session Handling" in `ITEST/AGENTS.md`, which keeps the login form
to the `003`–`008` sequence at the root of `itest.studio/multi/test-resources`. The V10 remediation plan requires a
second place, because "`200` with a session" can only be shown with a session that a real sign-in created. The
folder does not sign a scenario in.

`030`, `031` and `060` carry no `.resp`: the framework then expects `200` and ignores the body. `http.json` echoes
the request's headers and cookies, the session cookie among them, so it must never be compared or saved as a
golden. The password in `020` is `${ADMIN_PASSWORD}`, which `WebStudioTest` supplies at runtime; no credential is
written in this folder.

In `single` mode there is no login and every visitor holds `ADMIN`, so both endpoints stay `200` there, as the
`simple` suite's `info/sys.json` and `info/http.json` fixtures keep asserting.
