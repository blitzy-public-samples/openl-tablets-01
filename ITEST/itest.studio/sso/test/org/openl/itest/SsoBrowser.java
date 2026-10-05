package org.openl.itest;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

/**
 * Browser emulation for a Keycloak SSO login and SP-initiated logout across the two hosts (OpenL Studio
 * and the IdP). Follows redirects manually so each hop can be inspected, keeps a cookie jar, and submits
 * the Keycloak login and HTTP-POST binding forms.
 *
 * <p>The cookie jar clears the {@code Secure} flag: Keycloak sets {@code Secure;SameSite=None} cookies and
 * the test uses plain HTTP.
 *
 * @author Yury Molchan
 */
class SsoBrowser {

    private static final Pattern LOGIN_FORM_ACTION = Pattern.compile("(?s)id=\"kc-form-login\".*?action=\"([^\"]+)\"");
    private static final Pattern FORM_ACTION = Pattern.compile("(?s)<form[^>]*action=\"([^\"]+)\"");
    private static final Pattern HIDDEN_INPUT = Pattern.compile("(?s)name=\"([^\"]+)\"[^>]*?value=\"([^\"]*)\"");
    // V3: the Studio session cookie; Keycloak shares the host, so its cookies are told apart by this exact name
    private static final String SESSION_COOKIE = "JSESSIONID";

    private final URI base;
    private final HttpClient http;
    private final Duration requestTimeout;
    // V3: the cookie jar is kept, so a test can drop the Studio session cookie as a SameSite=Lax browser does
    private final CookieManager cookies = insecureCookieManager();

    SsoBrowser(URI base) {
        this.base = base;
        var builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(cookies); // V3: the kept cookie jar
        int connectTimeout = Integer.parseInt(System.getProperty("http.timeout.connect"));
        if (connectTimeout > 0) {
            builder.connectTimeout(Duration.ofMillis(connectTimeout));
        }
        this.http = builder.build();
        this.requestTimeout = Duration.ofMillis(Integer.parseInt(System.getProperty("http.timeout.read")));
    }

    /**
     * Logs in through the OpenID Connect authorization-code flow, ending on an authenticated session.
     */
    void loginViaOAuth2(String username, String password) throws Exception {
        var loginPage = followRedirects(get(base.resolve("/")));
        var afterCredentials = submitCredentials(loginPage.body(), username, password);
        followRedirects(afterCredentials);
    }

    /**
     * Logs in through SAML 2.0: posts the AuthnRequest auto-submit form to Keycloak, submits the
     * credentials, then posts the SAML response back to the assertion consumer service.
     */
    void loginViaSaml(String username, String password) throws Exception {
        var authnRequestForm = followRedirects(get(base.resolve("/")));
        var loginPage = followRedirects(submitAutoPostForm(authnRequestForm.body()));
        var samlResponse = submitCredentials(loginPage.body(), username, password);
        if (isRedirect(samlResponse)) {
            followRedirects(samlResponse);
        } else {
            followRedirects(submitAutoPostForm(samlResponse.body()));
        }
    }

    // V3: emulates a browser that does not send the SameSite=Lax session cookie on the IdP's cross-site POST
    /**
     * Logs in through SAML 2.0 as {@link #loginViaSaml(String, String)} does, optionally emulating a browser
     * that withholds the {@code SameSite=Lax} Studio session cookie on the IdP's cross-site HTTP-POST.
     *
     * <p>With {@code crossSiteCallback} set, every Studio {@code JSESSIONID} is removed from the cookie jar just
     * before the SAML response is posted to the assertion consumer service, so Studio has to match the response
     * to its AuthnRequest without the session. The IdP must then answer with the HTTP-POST binding form; a
     * redirect fails the login. With {@code false} the login is identical to the two-argument method.
     *
     * @param crossSiteCallback whether the SAML response is posted without the Studio session cookie
     */
    void loginViaSaml(String username, String password, boolean crossSiteCallback) throws Exception {
        var authnRequestForm = followRedirects(get(base.resolve("/")));
        finishSamlLogin(authnRequestForm, username, password, crossSiteCallback);
    }

    // V5: the Studio session ID as the first GET created it, for the session-fixation check
    /**
     * Logs in through the OpenID Connect authorization-code flow as {@link #loginViaOAuth2(String, String)}
     * does, and returns the Studio session ID that the first {@code GET /} established before the IdP redirect.
     *
     * @return the pre-login Studio {@code JSESSIONID} value, or {@code null} if Studio set none
     */
    @Nullable String loginViaOAuth2ReturningPreLoginSessionId(String username, String password) throws Exception {
        var loginPage = followRedirects(get(base.resolve("/")));
        var preLogin = studioSessionId();
        var afterCredentials = submitCredentials(loginPage.body(), username, password);
        followRedirects(afterCredentials);
        return preLogin;
    }

    // V5: the Studio session ID as the first GET created it; the cookie is kept through the callback
    /**
     * Logs in through SAML 2.0 as {@link #loginViaSaml(String, String)} does, keeping the Studio session cookie
     * through the callback, and returns the Studio session ID that the first {@code GET /} established before
     * the AuthnRequest was sent.
     *
     * @return the pre-login Studio {@code JSESSIONID} value, or {@code null} if Studio set none
     */
    @Nullable String loginViaSamlReturningPreLoginSessionId(String username, String password) throws Exception {
        var authnRequestForm = followRedirects(get(base.resolve("/")));
        var preLogin = studioSessionId();
        finishSamlLogin(authnRequestForm, username, password, false);
        return preLogin;
    }

    // V5: reads the Studio session cookie by its exact name, never a Keycloak cookie of the same host
    /**
     * Returns the value of the Studio {@code JSESSIONID} cookie currently in the jar, or {@code null} if there
     * is none. Callers compare values; they never print them.
     */
    @Nullable String studioSessionId() {
        return cookies.getCookieStore()
                .get(base)
                .stream()
                .filter(cookie -> SESSION_COOKIE.equals(cookie.getName()))
                .map(HttpCookie::getValue)
                .findFirst()
                .orElse(null);
    }

    /**
     * Sends a GET to a path relative to the OpenL Studio base URL without following redirects.
     */
    HttpResponse<String> get(String path) throws Exception {
        return get(base.resolve(path));
    }

    /**
     * Runs SP-initiated OpenID Connect logout, delivers it to Keycloak to end the IdP session, and returns
     * the IdP end-session endpoint.
     */
    String logoutViaOAuth2() throws Exception {
        var response = get(base.resolve("/logout"));
        if (!isRedirect(response)) {
            throw new AssertionError("Expected a redirect from /logout but got " + response.statusCode());
        }
        var endpoint = response.headers().firstValue("Location").orElseThrow();
        get(URI.create(endpoint)); // deliver the request so Keycloak ends the SSO session
        return endpoint;
    }

    /**
     * Runs SP-initiated SAML logout, delivers the LogoutRequest to Keycloak to end the IdP session, and
     * returns the IdP Single Logout Service endpoint. Handles the HTTP-Redirect and HTTP-POST bindings.
     */
    String logoutViaSaml() throws Exception {
        var response = get(base.resolve("/logout"));
        if (isRedirect(response)) {
            var location = response.headers().firstValue("Location").orElseThrow();
            if (!location.contains("SAMLRequest")) {
                throw new AssertionError("Logout redirect carries no SAMLRequest: " + location);
            }
            get(URI.create(location)); // deliver the request so Keycloak ends the SSO session
            return location;
        }
        if (!response.body().contains("SAMLRequest")) {
            throw new AssertionError("Logout issued no SAML LogoutRequest (status " + response.statusCode() + "):\n"
                    + response.body());
        }
        submitAutoPostForm(response.body()); // deliver the request so Keycloak ends the SSO session
        return htmlUnescape(group(response.body(), FORM_ACTION));
    }

    /**
     * Returns whether a fresh OpenID Connect login is challenged for credentials, i.e. the IdP session ended.
     */
    boolean oauth2ChallengesForLogin() throws Exception {
        return followRedirects(get(base.resolve("/"))).body().contains("kc-form-login");
    }

    /**
     * Returns whether a fresh SAML login is challenged for credentials, i.e. the IdP session ended.
     */
    boolean samlChallengesForLogin() throws Exception {
        var authnRequestForm = followRedirects(get(base.resolve("/")));
        return followRedirects(submitAutoPostForm(authnRequestForm.body())).body().contains("kc-form-login");
    }

    // V3: finishes a SAML login from the AuthnRequest auto-submit form; used only by the new login overloads
    private void finishSamlLogin(HttpResponse<String> authnRequestForm,
                                 String username,
                                 String password,
                                 boolean crossSiteCallback) throws Exception {
        var loginPage = followRedirects(submitAutoPostForm(authnRequestForm.body()));
        var samlResponse = submitCredentials(loginPage.body(), username, password);
        if (crossSiteCallback && isRedirect(samlResponse)) {
            throw new AssertionError("Expected the IdP HTTP-POST binding form, status " + samlResponse.statusCode());
        }
        if (isRedirect(samlResponse)) {
            followRedirects(samlResponse);
        } else {
            if (crossSiteCallback) {
                dropStudioSessionCookie();
            }
            followRedirects(submitAutoPostForm(samlResponse.body()));
        }
    }

    // V3: removes every Studio JSESSIONID from the jar; the messages never carry a cookie value
    private void dropStudioSessionCookie() {
        var store = cookies.getCookieStore();
        // collect first, so the store is not modified while its cookies are iterated
        List<HttpCookie> sessionCookies = store.get(base)
                .stream()
                .filter(cookie -> SESSION_COOKIE.equals(cookie.getName()))
                .toList();
        for (HttpCookie cookie : sessionCookies) {
            store.remove(base, cookie);
        }
        if (store.get(base).stream().anyMatch(cookie -> SESSION_COOKIE.equals(cookie.getName()))) {
            throw new AssertionError("Studio JSESSIONID still present before the cross-site SAML callback");
        }
    }

    private HttpResponse<String> submitCredentials(String loginPage, String username, String password) throws Exception {
        var action = URI.create(htmlUnescape(group(loginPage, LOGIN_FORM_ACTION)));
        var form = "username=" + encode(username) + "&password=" + encode(password) + "&credentialId=";
        return postForm(action, form);
    }

    /**
     * Posts every hidden input of an HTTP-POST binding auto-submit form to its action. SAML values are MIME
     * base64, so line breaks and CR entities are stripped first.
     */
    private HttpResponse<String> submitAutoPostForm(String html) throws Exception {
        var action = URI.create(htmlUnescape(group(html, FORM_ACTION)));
        var form = new StringBuilder();
        var matcher = HIDDEN_INPUT.matcher(html);
        while (matcher.find()) {
            var value = htmlUnescape(matcher.group(2).replaceAll("&#1[03];|\\s+", ""));
            if (!form.isEmpty()) {
                form.append('&');
            }
            form.append(encode(matcher.group(1))).append('=').append(encode(value));
        }
        return postForm(action, form.toString());
    }

    private HttpResponse<String> followRedirects(HttpResponse<String> response) throws Exception {
        var current = response;
        for (int hop = 0; hop < 10 && isRedirect(current); hop++) {
            var location = current.headers().firstValue("Location").orElseThrow();
            current = get(current.uri().resolve(location));
        }
        return current;
    }

    private HttpResponse<String> get(URI uri) throws Exception {
        return http.send(request(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postForm(URI uri, String body) throws Exception {
        var req = request(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder request(URI uri) {
        return HttpRequest.newBuilder(uri).timeout(requestTimeout);
    }

    // Keycloak sets Secure;SameSite=None cookies; clear Secure so they are sent over the test's plain HTTP.
    private static CookieManager insecureCookieManager() {
        return new CookieManager(null, CookiePolicy.ACCEPT_ALL) {
            @Override
            public void put(URI uri, Map<String, List<String>> responseHeaders) throws IOException {
                super.put(uri, responseHeaders);
                for (HttpCookie cookie : getCookieStore().getCookies()) {
                    cookie.setSecure(false);
                }
            }
        };
    }

    private static boolean isRedirect(HttpResponse<?> response) {
        return response.statusCode() >= 300 && response.statusCode() < 400;
    }

    private static String group(String html, Pattern pattern) {
        Matcher matcher = pattern.matcher(html);
        if (!matcher.find()) {
            throw new AssertionError("Pattern " + pattern + " not found in response:\n" + html);
        }
        return matcher.group(1);
    }

    private static String htmlUnescape(String value) {
        return value.replace("&amp;", "&")
                .replace("&#x2F;", "/")
                .replace("&#47;", "/")
                .replace("&quot;", "\"");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
