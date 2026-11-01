(function () {
    // redirect_uri is followed by this page's own JavaScript after
    // sign-in (and sent to the authorize/token endpoints, which
    // validate it against the client registration). Keep it
    // same-origin: a crafted login.html?redirect_uri=javascript:… or
    // cross-origin URL must not turn the post-login navigation into
    // XSS or an open redirect. Anything else falls back to the
    // console default below.
    function sanitizeRedirectUri(uri) {
        if (!uri) {
            return null;
        }
        try {
            var u = new URL(uri, window.location.origin);
            if (u.origin === window.location.origin) {
                return u.href;
            }
        } catch (e) {
            // fall through to null
        }
        return null;
    }

    var params = new URLSearchParams(window.location.search);
    var executionId = params.get('execution_id');
    var code = params.get('code');
    var loggedOut = params.get('logged_out') === '1';
    var urlRealm = params.get('realm');
    var urlClientId = params.get('client_id');
    var urlRedirectUri = sanitizeRedirectUri(params.get('redirect_uri'));
    var realm = urlRealm || 'master';

    var banner = document.getElementById('banner');
    var form = document.getElementById('login-form');
    var pkceRedirect = document.getElementById('pkce-redirect');
    var realmDisplay = document.getElementById('realm-display');
    var cardTitle = document.getElementById('card-title');

    function setRealmDisplay(r) {
        if (realmDisplay && r) {
            realmDisplay.textContent = 'Realm: ' + r;
        }
    }

    setRealmDisplay(realm);

    if (loggedOut) {
        banner.textContent = 'You have been signed out.';
        banner.classList.add('success');
    }

    var error = params.get('error');
    var errorDescription = params.get('error_description');
    var errorMessages = {
        'invalid_grant': 'Invalid username or password.',
        'access_denied': 'Access denied.',
        'invalid_request': 'Invalid request.',
        'authentication_challenge': 'Additional authentication required.',
        'unauthorized_client': 'Unauthorized client.',
        'invalid_client': 'Unknown or unauthorized client.',
        'invalid_scope': 'Invalid scope.',
        'server_error': 'Server error. Please try again later.',
        'unsupported_operation': 'Unsupported operation.',
        'login_required': 'Login required.',
        'request_not_supported': 'Request not supported.',
        'realm_not_found': 'Realm not found. Please check the URL.',
        'missing_realm': 'Missing realm. Please check the URL.'
    };
    if (error) {
        var msg = errorMessages[error] || 'Authentication failed. Please try again.';
        if (errorDescription) {
            msg += ' (' + errorDescription + ')';
        }
        banner.textContent = msg;
        banner.classList.add('error');
    }

    // Form login: populate the hidden fields and point the form at the
    // realm-scoped login endpoint FIRST — before any enhancement below
    // can throw (e.g. a JS engine without `fetch`), so the plain form
    // POST always carries ?realm=.
    if (executionId && !code) {
        document.getElementById('execution_id').value = executionId;
        document.getElementById('realm').value = realm;
        document.getElementById('login-form').action = '/api/v1/auth/login?realm=' + encodeURIComponent(realm);
    }

    // Login context: one request for the theme stylesheet, localized
    // strings, and the self-service affordances. Fired before the
    // early-return paths below (code callback, PKCE redirect,
    // error-only page) so their banners and spinner text localize
    // too; the PKCE redirect never waits on it. Any failure leaves
    // the static page exactly as-is. Guarded so JS engines without
    // `fetch` (e.g. HtmlUnit in the OIDC conformance suite) never
    // throw here — the form above is already fully functional.
    var contextUrl = '/realms/' + encodeURIComponent(realm) + '/login/context';
    if (executionId) {
        contextUrl += '?execution_id=' + encodeURIComponent(executionId);
    }
    function applyContextText(text) {
        var ctx;
        try {
            ctx = JSON.parse(text);
        } catch (e) {
            return;
        }
        if (ctx) applyLoginContext(ctx);
    }
    try {
        if (typeof window.fetch === 'function') {
            window.fetch(contextUrl, {
                headers: { 'Accept': 'application/json' }
            }).then(function (res) {
                return res.ok ? res.text() : null;
            }).then(function (text) {
                if (text) applyContextText(text);
            }).catch(function () {
                // Endpoint unavailable (older server, network error) —
                // the page stays exactly as rendered.
            });
        } else if (window.XMLHttpRequest) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', contextUrl, true);
            xhr.setRequestHeader('Accept', 'application/json');
            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4 && xhr.status >= 200 && xhr.status < 300) {
                    applyContextText(xhr.responseText);
                }
            };
            xhr.send();
        }
    } catch (ignored) {
        // No context available — the static page stays as-is.
    }

    // Handle OAuth2 callback: exchange code for tokens and show userinfo
    if (code) {
        handleCallback(code, realm, urlClientId, urlRedirectUri);
        return;
    }

    document.getElementById('sign-out-btn').addEventListener('click', function () {
        sessionStorage.removeItem('issuerd_code_verifier');
        sessionStorage.removeItem('issuerd_oidc_state');
        sessionStorage.removeItem('issuerd_access_token');
        sessionStorage.removeItem('issuerd_tokens');
        document.cookie = 'issuerd_code_verifier=; Max-Age=0; Path=/; Secure';
        window.location.href = window.location.pathname + '?realm=' + encodeURIComponent(realm);
    });

    if (!executionId) {
        // The authorization endpoint already rejected this request and
        // sent us here with an error (e.g. unknown client or realm).
        // Redirecting into the same authorize request would just fail
        // again and loop forever — show the error and stop.
        if (error) {
            form.style.display = 'none';
            pkceRedirect.style.display = 'none';
            return;
        }

        // PKCE entry point: hide form, show spinner, generate PKCE and redirect
        form.style.display = 'none';
        pkceRedirect.style.display = 'flex';

        var apiBase = window.location.origin;
        var clientId = urlClientId || 'admin-cli';
        var effectiveRealm = urlRealm || 'master';
        var redirectUri = urlRedirectUri || (window.location.origin + '/admin/console/callback');

        setRealmDisplay(effectiveRealm);

        function base64UrlEncode(buffer) {
            var bytes = new Uint8Array(buffer);
            var binary = '';
            for (var i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        function generateRandomString(length) {
            var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            var text = '';
            var randomValues = new Uint8Array(length);
            crypto.getRandomValues(randomValues);
            for (var i = 0; i < length; i++) {
                text += possible[randomValues[i] % possible.length];
            }
            return text;
        }

        function setCookie(name, value) {
            document.cookie = name + '=' + encodeURIComponent(value) + '; Path=/; SameSite=Lax; Secure';
        }
        function getCookie(name) {
            var match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
            return match ? decodeURIComponent(match[2]) : null;
        }

        var verifier = sessionStorage.getItem('issuerd_code_verifier') || getCookie('issuerd_code_verifier');
        var state = sessionStorage.getItem('issuerd_oidc_state');
        if (!verifier || !state) {
            verifier = generateRandomString(128);
            state = generateRandomString(32);
            sessionStorage.setItem('issuerd_code_verifier', verifier);
            sessionStorage.setItem('issuerd_oidc_state', state);
            sessionStorage.setItem('issuerd_oidc_realm', effectiveRealm);
            setCookie('issuerd_code_verifier', verifier);
        }

        var encoder = new TextEncoder();
        crypto.subtle.digest('SHA-256', encoder.encode(verifier)).then(function (digest) {
            var challenge = base64UrlEncode(digest);
            var authUrl = new URL(apiBase + '/realms/' + encodeURIComponent(effectiveRealm) + '/protocol/openid-connect/auth');
            authUrl.searchParams.set('client_id', clientId);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('scope', 'openid profile');
            authUrl.searchParams.set('redirect_uri', redirectUri);
            authUrl.searchParams.set('code_challenge', challenge);
            authUrl.searchParams.set('code_challenge_method', 'S256');
            authUrl.searchParams.set('state', state);
            window.location.href = authUrl.toString();
        }).catch(function (err) {
            pkceRedirect.style.display = 'none';
            form.style.display = 'block';
            var banner = document.getElementById('banner');
            banner.textContent = 'PKCE redirect failed: ' + (err && err.message ? err.message : String(err));
            banner.classList.add('error');
        });
        return;
    }

    // (Form-login hidden fields + action are set right after the error
    // banner handling above, before any enhancement that could throw.)

    // Applies the realm's login context: theme stylesheet, localized
    // strings, and the self-service affordances. Every field falls
    // back to the hardcoded English/palette when missing.
    function applyLoginContext(ctx) {
        // Theme stylesheet — inserted after the inline <style> so
        // the theme's :root custom properties win over the var()
        // fallbacks in the inline rules.
        var themeLink = document.createElement('link');
        themeLink.rel = 'stylesheet';
        themeLink.href = '/realms/' + encodeURIComponent(realm) + '/theme/login.css';
        var inlineStyle = document.getElementsByTagName('style')[0];
        if (inlineStyle && inlineStyle.parentNode) {
            inlineStyle.parentNode.insertBefore(themeLink, inlineStyle.nextSibling);
        } else {
            document.getElementsByTagName('head')[0].appendChild(themeLink);
        }

        if (ctx.locale) {
            document.documentElement.lang = ctx.locale;
        }

        var msg = function (key, fallback) {
            return (ctx.messages && ctx.messages[key]) || fallback;
        };

        if (cardTitle) cardTitle.textContent = msg('login.title', 'Sign In');
        var usernameLabel = document.querySelector('label[for="username"]');
        if (usernameLabel) usernameLabel.textContent = msg('login.username', 'Username');
        var passwordLabel = document.querySelector('label[for="password"]');
        if (passwordLabel) passwordLabel.textContent = msg('login.password', 'Password');
        var submitBtn = document.getElementById('login-submit');
        if (submitBtn) submitBtn.textContent = msg('login.submit', 'Sign In');
        var rememberMeSpan = document.querySelector('#remember-me-container span');
        if (rememberMeSpan) rememberMeSpan.textContent = msg('login.rememberMe', 'Remember me');
        var forgotLink = document.getElementById('forgot-password-link');
        if (forgotLink) forgotLink.textContent = msg('login.forgotPassword', 'Forgot password?');
        var registerLink = document.getElementById('register-link');
        if (registerLink) registerLink.textContent = msg('login.register', 'Register');
        var idpDivider = document.querySelector('#idp-section .idp-divider span');
        if (idpDivider) idpDivider.textContent = msg('login.or', 'or');
        if (realmDisplay) {
            realmDisplay.textContent = msg('login.realmPrefix', 'Realm:') + ' ' + realm;
        }
        var signOutBtn = document.getElementById('sign-out-btn');
        if (signOutBtn) signOutBtn.textContent = msg('login.signOut', 'Sign Out');
        if (loggedOut) {
            banner.textContent = msg('login.signedOut', 'You have been signed out.');
        }
        if (error) {
            var errorText = (ctx.messages && ctx.messages['login.error.' + error])
                || errorMessages[error]
                || msg('login.authFailed', 'Authentication failed. Please try again.');
            if (errorDescription) {
                errorText += ' (' + errorDescription + ')';
            }
            banner.textContent = errorText;
        }
        // Not in the code-callback path: handleCallback already
        // replaced the spinner text with "Completing sign in...".
        if (!code && pkceRedirect) {
            var redirectingSpan = pkceRedirect.querySelector('span');
            if (redirectingSpan) {
                redirectingSpan.textContent = msg('login.redirecting', 'Redirecting to sign in...');
            }
        }

        // Self-service affordances: reveal the matching controls
        // for the features the realm has enabled.
        if (ctx.remember_me_enabled) {
            var rememberMe = document.getElementById('remember-me-container');
            if (rememberMe) rememberMe.style.display = 'flex';
        }
        var showLinks = false;
        if (ctx.reset_password_allowed) {
            var forgot = document.getElementById('forgot-password-link');
            if (forgot) {
                forgot.href = '/realms/' + encodeURIComponent(realm) + '/login/reset-credentials';
                forgot.style.display = 'inline';
                showLinks = true;
            }
        }
        if (ctx.registration_enabled) {
            var register = document.getElementById('register-link');
            if (register) {
                register.href = '/realms/' + encodeURIComponent(realm) + '/login/register'
                    + (executionId ? '?execution_id=' + encodeURIComponent(executionId) : '');
                register.style.display = 'inline';
                showLinks = true;
            }
        }
        if (showLinks) {
            var links = document.getElementById('login-links');
            if (links) links.style.display = 'flex';
        }

        // Passwordless email-code mode: the realm logs in with a
        // one-time code mailed to the user's address, so no password
        // is collected. Runs after the generic label/reveal wiring
        // above so these overrides win.
        if (ctx.email_code_login === true) {
            var passwordInput = document.getElementById('password');
            if (passwordInput) {
                // A hidden-but-required input would block submission.
                passwordInput.required = false;
                passwordInput.style.display = 'none';
            }
            if (passwordLabel) passwordLabel.style.display = 'none';
            var rememberMeBox = document.getElementById('remember-me-container');
            if (rememberMeBox) rememberMeBox.style.display = 'none';
            if (forgotLink) forgotLink.style.display = 'none';
            var usernameInput = document.getElementById('username');
            if (usernameInput) {
                usernameInput.type = 'email';
                usernameInput.autocomplete = 'email';
            }
            if (usernameLabel) usernameLabel.textContent = msg('login.email', 'Email');
            if (submitBtn) submitBtn.textContent = msg('login.sendCode', 'Send code');
        }
        // External identity providers (brokers) — only relevant
        // mid-flow, when an execution_id is present.
        var idps = ctx.identity_providers;
        if (executionId && Array.isArray(idps) && idps.length > 0) {
            var idpSection = document.getElementById('idp-section');
            if (idpSection) {
                var added = 0;
                idps.forEach(function (idp) {
                    if (!idp || !idp.alias) return;
                    var link = document.createElement('a');
                    link.className = 'idp-btn';
                    link.href = '/realms/' + encodeURIComponent(realm)
                        + '/broker/' + encodeURIComponent(idp.alias)
                        + '/login?flow=' + encodeURIComponent(executionId);
                    link.textContent = msg('login.continueWith', 'Continue with {0}')
                        .replace('{0}', idp.display_name || idp.alias);
                    idpSection.appendChild(link);
                    added += 1;
                });
                if (added > 0) idpSection.style.display = 'block';
            }
        }

        // Client branding (OIDC registration §2): the paused flow's
        // client may carry logo/policy/tos URIs. Only absolute
        // http(s) URLs render — the attributes are admin/DCR input,
        // so a `javascript:` href must never make it into the DOM.
        var brandingUri = function (uri) {
            if (!uri) return null;
            try {
                var u = new URL(uri);
                return (u.protocol === 'https:' || u.protocol === 'http:') ? uri : null;
            } catch (e) {
                return null;
            }
        };
        var logoUri = brandingUri(ctx.client_logo_uri);
        if (logoUri) {
            var clientLogo = document.getElementById('client-logo');
            if (clientLogo) {
                clientLogo.src = logoUri;
                clientLogo.alt = ctx.client_name || '';
                clientLogo.style.display = 'block';
            }
        }
        var policyUri = brandingUri(ctx.client_policy_uri);
        var tosUri = brandingUri(ctx.client_tos_uri);
        if (policyUri || tosUri) {
            var clientLinks = document.getElementById('client-links');
            if (clientLinks) {
                if (policyUri) {
                    var policyLink = document.getElementById('client-policy-link');
                    if (policyLink) {
                        policyLink.href = policyUri;
                        policyLink.textContent = msg('login.policy', 'Privacy Policy');
                        policyLink.style.display = 'inline';
                    }
                }
                if (tosUri) {
                    var tosLink = document.getElementById('client-tos-link');
                    if (tosLink) {
                        tosLink.href = tosUri;
                        tosLink.textContent = msg('login.termsOfService', 'Terms of Service');
                        tosLink.style.display = 'inline';
                    }
                }
                clientLinks.style.display = 'block';
            }
        }
    }

    function handleCallback(code, urlRealm, urlClientId, urlRedirectUri) {
        form.style.display = 'none';
        pkceRedirect.style.display = 'flex';
        pkceRedirect.querySelector('span').textContent = 'Completing sign in...';

        var apiBase = window.location.origin;
        var clientId = urlClientId || 'admin-cli';
        var redirectUri = urlRedirectUri || (window.location.origin + '/admin/console/callback');
        var verifier = sessionStorage.getItem('issuerd_code_verifier');
        var realm = sessionStorage.getItem('issuerd_oidc_realm') || urlRealm;

        if (!verifier) {
            pkceRedirect.style.display = 'none';
            form.style.display = 'block';
            banner.textContent = 'Session expired. Please sign in again.';
            banner.classList.add('error');
            return;
        }

        var tokenUrl = apiBase + '/realms/' + encodeURIComponent(realm) + '/protocol/openid-connect/token';
        var tokenBody = 'grant_type=authorization_code'
            + '&code=' + encodeURIComponent(code)
            + '&redirect_uri=' + encodeURIComponent(redirectUri)
            + '&client_id=' + encodeURIComponent(clientId)
            + '&code_verifier=' + encodeURIComponent(verifier);

        fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: tokenBody
        }).then(function (res) {
            return res.json().then(function (data) {
                return { ok: res.ok, status: res.status, data: data };
            });
        }).then(function (result) {
            if (!result.ok) {
                throw new Error(result.data.error_description || result.data.error || 'Token exchange failed (' + result.status + ')');
            }
            var accessToken = result.data.access_token;
            var refreshToken = result.data.refresh_token || '';
            var idToken = result.data.id_token || '';
            var expiresIn = result.data.expires_in || 300;
            var rawTokens = sessionStorage.getItem('issuerd_tokens');
            var existingTokens = rawTokens ? JSON.parse(rawTokens) : {};
            if (existingTokens && typeof existingTokens === 'object' && existingTokens.accessToken) {
                // Legacy single-token format: migrate.
                var legacyRealm = localStorage.getItem('issuerd_realm') || 'master';
                var legacyToken = existingTokens;
                existingTokens = {};
                existingTokens[legacyRealm] = legacyToken;
            } else if (!existingTokens || typeof existingTokens !== 'object' || Array.isArray(existingTokens)) {
                existingTokens = {};
            }
            existingTokens[realm] = {
                accessToken: accessToken,
                refreshToken: refreshToken,
                idToken: idToken,
                expiresAt: Date.now() + expiresIn * 1000
            };
            sessionStorage.setItem('issuerd_tokens', JSON.stringify(existingTokens));
            sessionStorage.removeItem('issuerd_oidc_realm');
            localStorage.setItem('issuerd_realm', realm);
            window.location.href = redirectUri;
        }).catch(function (err) {
            pkceRedirect.style.display = 'none';
            form.style.display = 'block';
            banner.textContent = 'Sign in failed: ' + err.message;
            banner.classList.add('error');
        });
    }
})();
