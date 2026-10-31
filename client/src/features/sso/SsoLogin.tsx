import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { GoogleIcon } from './GoogleIcon';
import './SsoLogin.css';
import apiClient from '../../api/Api';

type Options = {
    sso_enabled: boolean;
    sso_start_url?: string;
    sso_display_name?: string;
};

export const SsoLogin = ({ children }: { children?: React.ReactNode }) => {
    const { t } = useTranslation();
    const [options, setOptions] = useState<Options>();
    const [failed, setFailed] = useState(false);
    const [loading, setLoading] = useState(true);
    const startPath = new URL('control/sso/oidc/start', window.location.href).pathname;
    const callbackFailed = new URLSearchParams(window.location.search).has('sso_error');

    useEffect(() => {
        let disposed = false;
        apiClient.makeRequest('auth/config', 'GET').then((result: Options) => {
            if (!disposed) setOptions(result);
        }).catch(() => {
            if (!disposed) setFailed(true);
        }).finally(() => {
            if (!disposed) setLoading(false);
        });
        return () => { disposed = true; };
    }, []);

    return (
        <div aria-live="polite" className="sso-login">
            {loading && <p>{t('sso_loading')}</p>}
            {(failed || callbackFailed || (options?.sso_enabled && options.sso_start_url !== startPath)) && <p role="alert">{t('sso_error')}</p>}
            {options?.sso_enabled && options.sso_start_url === startPath && (
                <a className="sso-login__button" href={startPath}>
                    {options.sso_display_name?.toLowerCase() === 'google' && <GoogleIcon />}
                    {t('sso_sign_in', { provider: options.sso_display_name || 'SSO' })}
                </a>
            )}
            {!loading && !options?.sso_enabled && children}
        </div>
    );
};
