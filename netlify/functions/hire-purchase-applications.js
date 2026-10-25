const API_BASE = 'https://api.netlify.com/api/v1';
const crypto = require('crypto');
const ROLES_CLAIM = 'https://treasurerock.com/roles';

function jsonResponse(statusCode, payload) {
    return {
        statusCode,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    };
}

async function readJson(response, context) {
    if (!response.ok) {
        console.error(`${context} returned HTTP ${response.status}.`);
        throw new Error(`${context} request failed.`);
    }
    return response.json();
}

async function verifyAccessToken(token, domain, audience) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    let header;
    let claims;
    try {
        header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch {
        return null;
    }
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') return null;

    const issuer = `https://${domain.replace(/^https?:\/\//, '').replace(/\/+$/, '')}/`;
    const jwksResponse = await fetch(`${issuer}.well-known/jwks.json`);
    const jwks = await readJson(jwksResponse, 'Auth0 signing keys');
    const key = jwks.keys.find(item => item.kid === header.kid && item.kty === 'RSA');
    if (!key) return null;

    let publicKey;
    try {
        publicKey = crypto.createPublicKey({ key, format: 'jwk' });
    } catch {
        return null;
    }
    const signedContent = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2], 'base64url');
    if (!crypto.verify('RSA-SHA256', signedContent, publicKey, signature)) return null;

    const now = Math.floor(Date.now() / 1000);
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== issuer || !audiences.includes(audience) ||
        !Number.isFinite(claims.exp) || claims.exp <= now ||
        (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now))) {
        return null;
    }
    return claims;
}

exports.handler = async function (event) {
    if (event.httpMethod !== 'GET') {
        return jsonResponse(405, { error: 'Method not allowed.' });
    }

    const headers = event.headers || {};
    const authorization = headers.authorization || headers.Authorization || '';
    const tokenMatch = /^Bearer\s+(.+)$/i.exec(authorization);
    if (!tokenMatch) {
        return jsonResponse(401, { error: 'Authentication required.' });
    }

    const siteId = process.env.SITE_ID;
    const accessToken = process.env.NETLIFY_ACCESS_TOKEN;
    const auth0Domain = process.env.AUTH0_DOMAIN;
    const auth0Audience = process.env.AUTH0_AUDIENCE;
    if (!siteId || !accessToken || !auth0Domain || !auth0Audience) {
        console.error('Missing required configuration for Netlify Forms or Auth0.');
        return jsonResponse(500, { error: 'Application service is not configured.' });
    }

    try {
        const claims = await verifyAccessToken(tokenMatch[1], auth0Domain, auth0Audience);
        if (!claims) return jsonResponse(401, { error: 'Authentication required.' });
        const roles = claims[ROLES_CLAIM];
        if (!Array.isArray(roles)) return jsonResponse(403, { error: 'Not authorized to view applications.' });
        if (!roles.includes('staff') && !roles.includes('admin')) {
            return jsonResponse(403, { error: 'Not authorized to view applications.' });
        }

        const apiHeaders = { Authorization: `Bearer ${accessToken}` };
        const formsResponse = await fetch(`${API_BASE}/sites/${encodeURIComponent(siteId)}/forms`, {
            headers: apiHeaders
        });
        const forms = await readJson(formsResponse, 'Netlify forms');
        const form = forms.find(item => item.name === 'hire-purchase');
        if (!form) return jsonResponse(200, []);

        const submissions = [];
        for (let page = 1; ; page += 1) {
            const url = new URL(`${API_BASE}/sites/${encodeURIComponent(siteId)}/submissions`);
            url.searchParams.set('form_id', form.id);
            url.searchParams.set('per_page', '100');
            url.searchParams.set('page', String(page));
            const response = await fetch(url, { headers: apiHeaders });
            const currentPage = await readJson(response, 'Netlify form submissions');
            if (!Array.isArray(currentPage)) {
                throw new Error('Netlify returned an invalid submissions response.');
            }
            submissions.push(...currentPage);
            if (currentPage.length < 100) break;
        }
        return jsonResponse(200, submissions);
    } catch (error) {
        console.error('Unable to load hire purchase submissions.', error);
        return jsonResponse(502, { error: 'Unable to load applications right now.' });
    }
};
