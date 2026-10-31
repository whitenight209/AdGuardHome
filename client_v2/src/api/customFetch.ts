import { HTML_PAGES } from '../helpers/constants';
import { ApiError } from './httpError';
import { sendRequest } from './transport';

export { ApiError } from './httpError';

type CustomFetchOptions = RequestInit & {
    skipAuthRedirect?: boolean;
};

/**
 * Custom fetch mutator for orval-generated API client.
 *
 * Custom fetch wrapper providing AdGuard Home-specific behaviors:
 * - Sets `Content-Type: application/json` on requests with a body
 * - Parses response as JSON (falls back to raw text if JSON.parse fails)
 * - On 401/403 outside authentication pages → redirects browser to login
 *   and returns `false` (does not throw)
 * - On 401/403 on authentication pages → throws ApiError normally
 * - Throws Error with format `${path} | ${data} | ${status}` for all
 *   other non-ok responses
 * - On empty response body → returns empty string ''
 * - On 204 → returns empty string ''
 */
export const customFetch = async <T>(url: string, options?: CustomFetchOptions): Promise<T> => {
    const { skipAuthRedirect, ...fetchOptions } = options || {};

    const fullUrl = url;
    const headers: Record<string, string> = {};

    // Preserve any headers passed in options
    if (fetchOptions.headers) {
        const incomingHeaders = fetchOptions.headers as Record<string, string>;
        Object.assign(headers, incomingHeaders);
    }

    try {
        const response = await sendRequest(fullUrl, {
            ...fetchOptions,
            headers,
        });

        const text = await response.text();
        const data: T = text
            ? (() => {
                  try {
                      return JSON.parse(text);
                  } catch {
                      return text;
                  }
              })()
            : ('' as unknown as T);

        if (!response.ok) {
            const { pathname } = window.location;
            const shouldRedirect = ![
                HTML_PAGES.LOGIN,
                HTML_PAGES.INSTALL,
                HTML_PAGES.FORGOT_PASSWORD,
            ].some((page) => pathname.endsWith(page));

            if ([401, 403].includes(response.status) && shouldRedirect && !skipAuthRedirect) {
                const loginPageUrl = new URL('login.html', window.location.href).href;
                window.location.replace(loginPageUrl);
                return false as unknown as T;
            }

            throw new ApiError(
                `${fullUrl} | ${typeof data === 'string' ? data : JSON.stringify(data)} | ${response.status}`,
                response.status,
            );
        }

        return data;
    } catch (error) {
        if (error instanceof ApiError || (error instanceof Error && error.message.includes('|'))) {
            throw error;
        }

        throw new Error(`${fullUrl} | ${error instanceof Error ? error.message : String(error)}`);
    }
};

export default customFetch;
