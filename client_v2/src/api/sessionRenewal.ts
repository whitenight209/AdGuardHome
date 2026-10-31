import { ApiError } from './httpError';

let renewal: Promise<boolean> | undefined;

// Serialize within this app and across same-origin tabs. A second tab probes
// the shared access cookie after taking the lock instead of replaying a token.
export const renewSession = (): Promise<boolean> => {
    if (renewal) return renewal;
    const refreshUrl = new URL('control/sso/refresh', window.location.href);
    const perform = async (): Promise<boolean> => {
        const profile = await fetch(new URL('control/profile', window.location.href), {
            credentials: 'same-origin',
            cache: 'no-store',
        });
        if (profile.ok) return true;
        if (profile.status !== 401) throw new ApiError('Session check failed', profile.status);
        const result = await fetch(refreshUrl, {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
        });
        if (result.status === 204) return true;
        if ([401, 404].includes(result.status)) return false;
        throw new ApiError('Session renewal failed', result.status);
    };
    const serialized = async (): Promise<boolean> => {
        if (navigator.locks)
            return await navigator.locks.request(`agh-sso:${refreshUrl.href}`, perform);
        return perform();
    };
    renewal = serialized().finally(() => {
        renewal = undefined;
    });
    return renewal;
};
