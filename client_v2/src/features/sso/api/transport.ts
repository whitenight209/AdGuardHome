import { ApiError } from 'panel/api/httpError';
import type { RequestTransport } from 'panel/api/transport';
import { renewSession } from './sessionRenewal';

// Keep renewal and the one-retry policy in the fork-owned extension, rather
// than teaching the shared request parser about SSO endpoints and cookies.
export const rememberedTransport: RequestTransport = async (url, options) => {
    if (url.endsWith('/sso/refresh')) {
        if (!(await renewSession())) throw new ApiError('Session renewal required | 401', 401);
        return new Response(null, { status: 204 });
    }

    const response = await fetch(url, options);
    if (
        response.status === 401 &&
        !url.endsWith('/login') &&
        !url.includes('/sso/oidc/') &&
        (await renewSession())
    ) {
        return fetch(url, options);
    }
    return response;
};
