import type {
    AuthConfig,
    CompleteSSOParams,
    RevokeSSODeviceBody,
    SSODevice,
    StartSSOParams,
} from './model';

import { customFetch } from '../../../api/customFetch';
export const getGetAuthConfigUrl = () => {
    return `control/auth/config`;
};

/**
 * @summary Get public web login options
 */
export const getAuthConfig = async (options?: RequestInit): Promise<AuthConfig> => {
    return customFetch<AuthConfig>(getGetAuthConfigUrl(), {
        ...options,
        method: 'GET',
    });
};

export const getRefreshSSOUrl = () => {
    return `control/sso/refresh`;
};

/**
 * @summary Rotate a remembered-device cookie and issue a short session
 */
export const refreshSSO = async (options?: RequestInit): Promise<void> => {
    return customFetch<void>(getRefreshSSOUrl(), {
        ...options,
        method: 'POST',
    });
};

export const getGetSSODevicesUrl = () => {
    return `control/sso/devices`;
};

/**
 * @summary List remembered devices owned by the signed-in SSO user
 */
export const getSSODevices = async (options?: RequestInit): Promise<SSODevice[]> => {
    return customFetch<SSODevice[]>(getGetSSODevicesUrl(), {
        ...options,
        method: 'GET',
    });
};

export const getRevokeSSODeviceUrl = () => {
    return `control/sso/devices/revoke`;
};

/**
 * @summary Revoke one remembered device owned by the SSO user
 */
export const revokeSSODevice = async (
    revokeSSODeviceBody: RevokeSSODeviceBody,
    options?: RequestInit,
): Promise<void> => {
    return customFetch<void>(getRevokeSSODeviceUrl(), {
        ...options,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...options?.headers },
        body: JSON.stringify(revokeSSODeviceBody),
    });
};

export const getStartSSOUrl = (params?: StartSSOParams) => {
    const normalizedParams = new URLSearchParams();

    Object.entries(params || {}).forEach(([key, value]) => {
        if (value !== undefined) {
            normalizedParams.append(key, value === null ? 'null' : String(value));
        }
    });

    const stringifiedParams = normalizedParams.toString();

    return stringifiedParams.length > 0
        ? `control/sso/oidc/start?${stringifiedParams}`
        : `control/sso/oidc/start`;
};

/**
 * @summary Begin OIDC sign-in using top-level browser navigation
 */
export const startSSO = async (
    params?: StartSSOParams,
    options?: RequestInit,
): Promise<unknown> => {
    return customFetch<unknown>(getStartSSOUrl(params), {
        ...options,
        method: 'GET',
    });
};

export const getCompleteSSOUrl = (params: CompleteSSOParams) => {
    const normalizedParams = new URLSearchParams();

    Object.entries(params || {}).forEach(([key, value]) => {
        if (value !== undefined) {
            normalizedParams.append(key, value === null ? 'null' : String(value));
        }
    });

    const stringifiedParams = normalizedParams.toString();

    return stringifiedParams.length > 0
        ? `control/sso/oidc/callback?${stringifiedParams}`
        : `control/sso/oidc/callback`;
};

/**
 * @summary Consume the browser-bound OIDC authorization response
 */
export const completeSSO = async (
    params: CompleteSSOParams,
    options?: RequestInit,
): Promise<unknown> => {
    return customFetch<unknown>(getCompleteSSOUrl(params), {
        ...options,
        method: 'GET',
    });
};
