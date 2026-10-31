import { createSignal, onCleanup, onMount, Show, type JSX } from 'solid-js';
import intl from 'panel/common/intl';
import { getAuthConfig } from 'panel/api/generated';
import type { AuthConfig } from 'panel/api/model';

import { GoogleIcon } from './GoogleIcon';
import s from './SsoLogin.module.pcss';

export const SsoLogin = (props: { children?: JSX.Element }) => {
    const [options, setOptions] = createSignal<AuthConfig>();
    const [failed, setFailed] = createSignal(false);
    const [loading, setLoading] = createSignal(true);
    const startPath = new URL('control/sso/oidc/start', window.location.href).pathname;
    const callbackFailed = new URLSearchParams(window.location.search).has('sso_error');
    let disposed = false;
    onCleanup(() => {
        disposed = true;
    });
    onMount(async () => {
        try {
            const result = await getAuthConfig();
            if (!disposed) setOptions(result);
        } catch {
            if (!disposed) setFailed(true);
        } finally {
            if (!disposed) setLoading(false);
        }
    });

    return (
        <div aria-live="polite">
            <Show when={loading()}>
                <p>{intl.getMessage('sso_loading')}</p>
            </Show>
            <Show
                when={
                    failed() ||
                    callbackFailed ||
                    (options()?.sso_enabled && options()?.sso_start_url !== startPath)
                }
            >
                <p role="alert">{intl.getMessage('sso_error')}</p>
            </Show>
            <Show when={options()?.sso_enabled && options()?.sso_start_url === startPath}>
                <a class={s.button} href={startPath}>
                    <Show when={options()?.sso_display_name?.toLowerCase() === 'google'}>
                        <GoogleIcon />
                    </Show>
                    {intl.getMessage('sso_sign_in', {
                        provider: options()?.sso_display_name ?? 'SSO',
                    })}
                </a>
            </Show>
            <Show when={!loading() && !options()?.sso_enabled}>{props.children}</Show>
        </div>
    );
};
