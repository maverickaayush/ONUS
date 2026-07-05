// ZAP authentication script - mirrors backend/tasks/owasp.py's
// _make_session()/_FormFieldExtractor exactly (Python twin of this file):
// GET the login page fresh (to capture a per-session CSRF token or any
// other hidden field the server issues), extract every <input name=
// value=> pair on the page, override the username/password fields with the
// configured credentials, then POST all of it back. Submits "everything a
// browser would" rather than special-casing known CSRF field names - this
// is what made owasp.py's own login succeed against DVWA (user_token +
// Login submit-button field) and is expected to cover NodeGoat's _csrf the
// same way.
//
// Required params (set via zap.authentication.set_authentication_method's
// scriptBasedAuthentication configparams - see webscan.py):
//   loginUrl, usernameField, passwordField
// Credential params (set via zap.users.set_authentication_credentials):
//   username, password

function authenticate(helper, paramsValues, credentials) {
	var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
	var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
	var URI = Java.type("org.apache.commons.httpclient.URI");

	var loginUrl = paramsValues.get("loginUrl");
	var usernameField = paramsValues.get("usernameField");
	var passwordField = paramsValues.get("passwordField");

	// --- Step 1: GET the login page fresh ---
	var getUri = new URI(loginUrl, false);
	var getMsg = helper.prepareMessage();
	getMsg.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.GET, getUri, HttpHeader.HTTP10));
	helper.sendAndReceive(getMsg);
	var body = getMsg.getResponseBody().toString();

	// --- Step 2: extract every <input name=... value=...> on the page ---
	// Two alternated patterns since attribute order (name before/after
	// value) varies by app - same reasoning as owasp.py's HTMLParser-based
	// extractor, just regex instead since this JS environment has no
	// convenient DOM parser available.
	var fields = {};
	var re1 = /<input\b[^>]*\bname=["']([^"']+)["'][^>]*\bvalue=["']([^"']*)["']/gi;
	var re2 = /<input\b[^>]*\bvalue=["']([^"']*)["'][^>]*\bname=["']([^"']+)["']/gi;
	var m;
	while ((m = re1.exec(body)) !== null) {
		fields[m[1]] = m[2];
	}
	while ((m = re2.exec(body)) !== null) {
		if (!(m[2] in fields)) fields[m[2]] = m[1];
	}

	// --- Step 3: override username/password with the real credentials ---
	fields[usernameField] = credentials.getParam("username");
	fields[passwordField] = credentials.getParam("password");

	// --- Step 4: build the POST body ---
	var parts = [];
	for (var key in fields) {
		if (fields.hasOwnProperty(key)) {
			parts.push(encodeURIComponent(key) + "=" + encodeURIComponent(fields[key]));
		}
	}
	var requestBody = parts.join("&");

	// --- Step 5: POST back to the login URL, explicitly carrying forward
	// whatever session cookie the GET above just set. ZAP calls authenticate()
	// once per re-authentication it decides it needs (observed: many times
	// during a single spider run, not just once), and does NOT implicitly
	// share a cookie jar between the two helper.sendAndReceive() calls within
	// one invocation - the CSRF token extracted above is only valid for the
	// exact session the GET established, so without this the POST goes out
	// under a different (or no) session and the login is silently rejected.
	// Confirmed by direct testing: a single authenticate() call succeeded
	// (proxying one request through ZAP worked), but the spider's repeated
	// re-authentications mostly failed until this was added - visible in
	// ZAP's own logs as "Shutting down ZAP due to High Level Insight: HIGH :
	// EXCEEDED_HIGH : insight.auth.failure : 100" (its own watchdog for
	// exactly this failure pattern), not a crash or OOM.
	var setCookieHeaders = getMsg.getResponseHeader().getHeaders("Set-Cookie");
	var cookieParts = [];
	if (setCookieHeaders !== null) {
		for (var i = 0; i < setCookieHeaders.size(); i++) {
			cookieParts.push(setCookieHeaders.get(i).split(";")[0]);
		}
	}

	var postUri = new URI(loginUrl, false);
	var postMsg = helper.prepareMessage();
	postMsg.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.POST, postUri, HttpHeader.HTTP10));
	if (cookieParts.length > 0) {
		postMsg.getRequestHeader().setHeader("Cookie", cookieParts.join("; "));
	}
	postMsg.setRequestBody(requestBody);
	postMsg.getRequestHeader().setContentLength(postMsg.getRequestBody().length());
	helper.sendAndReceive(postMsg);

	return postMsg;
}

function getRequiredParamsNames() {
	return ["loginUrl", "usernameField", "passwordField"];
}

function getOptionalParamsNames() {
	return [];
}

function getCredentialsParamsNames() {
	return ["username", "password"];
}
