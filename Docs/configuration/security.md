## Enabling Security in the OpenL Tablets Rule Services Web Service

OpenL Tablets Rule Services web service comes with the simple implementation of the OAuth2 authentication.
To enable it, define the following properties:

```properties
ruleservice.authentication.enabled = true
ruleservice.authentication.iss = https://accounts.google.com
ruleservice.authentication.jwks = https://www.googleapis.com/oauth2/v3/certs
#ruleservice.authentication.aud = https://openl-tablets.org
```

<!-- V2: only the health, info and config admin paths bypass the JWT check -->
When `ruleservice.authentication.enabled = true`, only requests under the following `/admin/` prefixes are served
without a JWT:

* `/admin/healthcheck/`
* `/admin/info/`
* `/admin/config/`

Every other `/admin/` path requires a valid JWT: a token signed by a key from the `ruleservice.authentication.jwks` key
set (unsigned `alg: none` tokens are refused), carrying an `exp` claim that has not passed (30 seconds of clock skew is
allowed), issued by the configured `ruleservice.authentication.iss` and addressed to one of the comma-separated
`ruleservice.authentication.aud` values. This includes `/admin/deploy` (available when
`ruleservice.deployer.enabled = true`), `/admin/services`, `/admin/ui/info`, `/admin/swagger-ui.json`, and any
`openapi.json` or `openapi.yaml` document under `/admin/`. Service OpenAPI documents outside `/admin/`, such as
`/<service>/openapi.json`, remain public. An `/admin/` request whose path holds a `.` or `..` segment, also
percent-encoded as `%2e`, is not exempt even when it resolves under one of the three prefixes above, and requires a
valid JWT.

Send the token in the `Authorization` header:

```
Authorization: Bearer ${JWT_TOKEN}
```

A request without the `Authorization` header receives `401` with `WWW-Authenticate: Basic`. A request whose
`Authorization` header does not carry a valid Bearer JWT receives `403`: an invalid or expired token, or any other
scheme, such as `Basic`.

The built-in Rule Services web page cannot attach a token, so its administrative actions (the service list, service
errors, `MANIFEST.MF`, and deployment upload, download and delete) are unavailable while authentication is enabled. Its
"Properties" (`admin/config/application.properties`) and "System Info" (`admin/info/sys.json`) links keep working. The
Swagger UI page (`swagger-ui.html`) still opens but cannot list the services while authentication is enabled, because it
reads that list from `admin/swagger-ui.json`; the per-service `/<service>/openapi.json` documents stay public.

In case when the default security does not meet the requirements, a custom implementation can be added as follows:

```java
package org.openl.rules.ruleservice.spring;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import org.openl.rules.ruleservice.api.AuthorizationChecker;

@Component
@Order(2)
public class BasicAuthorizationChecker implements AuthorizationChecker {

    @Override
    public boolean authorize(HttpServletRequest request) {
        var basicRealm = request.getHeader("Authorization");
        var path = request.getPathInfo();
        return isRequiredAuthorization(path) && isValidRealm(basicRealm);
    }

}
```

There can be several Spring beans. The order of authorization can be defined by the `@Order` annotation.
The authorization is successful if any of checkers returns `true`.
A custom access denied handler can be registered to be called when no checkers return `true`.

```java
package org.openl.rules.ruleservice.spring;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import org.openl.rules.ruleservice.api.AccessDeniedHandler;

@Order(0)
@Component
public class BasicAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
```
