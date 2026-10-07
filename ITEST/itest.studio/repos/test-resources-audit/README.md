# V11 security audit fixtures

## Purpose

These fixtures drive the authentication, personal access token (PAT) and ACL events that V11 writes to the logger
`org.openl.security.audit`. `SecurityAuditLogITest` asserts the lines captured per folder: every audit line written
between two of its `client.test` calls belongs to the folder that ran.

## How it runs

- `SecurityAuditLogITest` runs the folders one by one, each with its own `client.test` call. `WebStudioTest` never
  runs them, because it runs `test-resources` only.
- The `repos` server runs `user.mode=multi`. There is no `itest.env`: every value comes from `localEnv`.
- Each `client.test` call resets the cookies, so the requests of one folder share one cookie scope, and its files run
  in name order. A request with its own `Cookie: NO_JSESSIONID=noAuth` header is sent without the session cookie of
  its folder, so its `Authorization` header alone authenticates it.
- The test asserts the folder names below in this order. Adding, renaming or reordering a folder changes the asserted
  segments, so the names are fixed.

## Folders

Each item gives a folder and what it does, and its sub-item the audit lines asserted for it.

- `010-setup`: Creates the four local users `audit_form`, `audit_basic`, `audit_lock` and `audit_delete`, and nothing
  else. Multi mode has no group API (`/rest/admin/management/groups` answers `404`), so the group
  `${SECRET_LOOKING_GROUP}` is created by the bulk entry in `090` and its SID removed by the bulk overwrite in `120`
  - Audit lines asserted: None counted: the lines are the administrator's setup logins
- `020-login`: Signs `audit_form` in through the login form with a wrong and then the right password, and sends an HTTP
  Basic request for `audit_basic` with the right and then a wrong password
  - Audit lines asserted: One `auth.success` and one `auth.failure` per user
- `030-lockout`: Sends five requests with HTTP Basic and a wrong password for `audit_lock`. The fifth engages the lock
  - Audit lines asserted: Five `auth.failure` and one `auth.lockout` (`outcome=locked`) for `audit_lock`
- `040-pat-use`: `010` presents the administrator's valid token without a session. HTTP Basic opens no session, so `020`
  opens the administrator's session with a form login. `030` presents the same token on that session of the same user,
  which the token does not replace. `040` presents, without a session, a generated token that parses but matches no
  stored token, and gets `401`
  - Audit lines asserted: Two `auth.success` lines with `method=pat` and the token's public ID, and one `auth.failure`
    with `method=pat`, `user="-"` and the public ID of the invalid token
- `050-pat-revoke`: Deletes the token by its public ID `{PAT_PUBLIC_ID}`
  - Audit lines asserted: One `pat.revoke` with that public ID
- `060-project-create`: Creates the project `{SECRET_LOOKING_PROJECT}` from an archive in the `design` database
  repository, with the default grant. The archive is `test-resources/task_EPBDS-15595/project.zip`, referenced and not
  copied. A database repository is not wrapped in `MappedRepository`, whose WARN lines name project paths
  - Audit lines asserted: At least one `acl.change` with `changes` ≥ 1, listing `createAcl` or `updateAcl`
- `070-project-acl-put`: Grants `VIEWER` on the project to `audit_basic`
  - Audit lines asserted: At least one `acl.change` with `changes` ≥ 1, listing `updateAcl` or `createAcl`
- `080-project-acl-delete`: Revokes that `VIEWER` grant of `audit_basic`
  - Audit lines asserted: At least one `acl.change` with `changes` ≥ 1, listing `updateAcl` or `deleteAcl`
- `090-bulk-acl`: `010` reads the ACL configuration. `020` overwrites it with one `POST /rest/acls` of 4 entries on the
  `design` repository: `audit_basic`, `audit_form`, `audit_delete` and the group `${SECRET_LOOKING_GROUP}`, which the
  overwrite creates. An overwrite removes the SID of every user it does not list, and deleting a user writes
  `acl.change` only when its SID exists, whether or not the SID still holds an entry. `audit_delete` is therefore
  listed: the overwrite does not remove its SID, and its entry creates that SID if it is missing, so `110` finds it
  - Audit lines asserted: Exactly one `acl.change`, with `changes` ≥ 4, the number of entries the test counts in `020`
- `100-project-delete`: Deletes the project, which removes its ACL (`deleteAcl`)
  - Audit lines asserted: At least one `acl.change` listing `deleteAcl`
- `110-user-delete`: Deletes `audit_delete`, which removes its SID (`deleteSid`)
  - Audit lines asserted: At least one `acl.change` listing `deleteSid`
- `120-group-delete`: A second bulk overwrite that lists only the administrator, so it removes the SID of
  `${SECRET_LOOKING_GROUP}` (`deleteSid`)
  - Audit lines asserted: At least one `acl.change` listing `deleteSid`

## Environment values

The test puts these 16 values into `localEnv` at runtime. It derives the two `ADMIN_*` values from the configured
administrator, takes `PAT_TOKEN` and `PAT_PUBLIC_ID` from the token it creates, and generates the rest. None is ever
written to a file:
`ADMIN_AUTH_TOCKEN`, `ADMIN_PASSWORD`, `AUDIT_FORM_PASSWORD`, `AUDIT_FORM_WRONG_PASSWORD`, `AUDIT_BASIC_PASSWORD`,
`AUDIT_BASIC_BASIC`, `AUDIT_BASIC_WRONG_BASIC`, `AUDIT_LOCK_PASSWORD`, `AUDIT_LOCK_WRONG_BASIC`,
`AUDIT_DELETE_PASSWORD`, `PAT_TOKEN`, `PAT_PUBLIC_ID`, `INVALID_PAT_TOKEN`, `SECRET_LOOKING_PROJECT`,
`SECRET_LOOKING_PROJECT_ID` and `SECRET_LOOKING_GROUP`.

- Headers and JSON or form-urlencoded bodies read a value as `${NAME}`, request paths as `{NAME}`. A multipart body
  is sent as written, so `060-project-create` names its project in the path only.
- A `{…}` value is inserted into the URL verbatim, without encoding, so it must be URL-safe and hold no `$` or `\`.
- `SECRET_LOOKING_PROJECT_ID` is the Base64 of `design:<project name>`, and holds no `/` or `+`.
- `SECRET_LOOKING_GROUP` is also inserted into a JSON body, so it must be safe there as well.

## Secret hygiene

- No fixture creates a PAT. The test creates it in Java and passes the token and its public ID through `localEnv`.
- No `.resp` compares a body that could carry a credential or echo a generated name. Such a response is matched with
  the whole-body wildcard `***` (`040-pat-use/040`, `060-project-create/010`), or has no `.resp`
  (`020-login/030`, `040-pat-use/010` and `030`, `090-bulk-acl/010`), so that the framework expects `200` and
  ignores the body.
- No file here holds a literal password, Basic value or token.

## Format

The `.req` and `.resp` files use CRLF line endings. They carry no comment line, because the harness reads the first
line as the request or status line and every following line up to the first empty one as a header.
