package org.openl.rules.ruleservice.servlet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NormalizedRequestUriTest {

    @Test
    void nullUri_isNotNormalized() {
        assertFalse(NormalizedRequestUri.isNormalized(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"",
            "/",
            "/admin/info/sys.json",
            "/webservice/admin/info/sys.json",
            "/simple/openapi.json",
            "/admin/deploy/rules-to-deploy.zip",
            "//admin//info/",
            "/a/..b/c",
            "/a/b../c",
            "/a/.hidden",
            "/a/b;x=1/c",
            "/a/.../c",
            "/a/%2e%2e%2e/c",
            "/a/%2ex/c",
            "/a/%2/c",
            "/a/%2f../c",
            "/a/%252e%252e/c",
            "admin",
            "/a/;x/c"})
    void uriWithoutDotSegment_isNormalized(String uri) {
        assertTrue(NormalizedRequestUri.isNormalized(uri));
    }

    @ParameterizedTest
    @ValueSource(strings = {".",
            "..",
            "/.",
            "/..",
            "/./admin/info/",
            "/admin/deploy/../info/sys.json",
            "/admin/deploy/x/../../info/a",
            "/webservice/admin/deploy/../info/sys.json",
            "/admin/deploy/../../deployed-rules/openapi.json",
            "/admin/info/..",
            "/admin/info/.",
            "/admin/deploy/%2e%2e/healthcheck/readiness",
            "/admin/deploy/%2E%2E/healthcheck/readiness",
            "/admin/deploy/%2e%2E/healthcheck/readiness",
            "/admin/deploy/.%2e/healthcheck/readiness",
            "/admin/deploy/%2E./healthcheck/readiness",
            "/admin/deploy/%2e/info/a",
            "/admin/deploy/..;x/config/application.properties",
            "/admin/deploy/.;x=1/info/a",
            "/admin/deploy/%2e%2e;/info/a",
            "/admin/info/a/../"})
    void uriWithDotSegment_isNotNormalized(String uri) {
        assertFalse(NormalizedRequestUri.isNormalized(uri));
    }
}
