import { createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import { getAuthConfig, getSSODevices, revokeSSODevice } from 'panel/features/sso/api/generated';
import { ApiError } from 'panel/api/customFetch';
import type { SSODevice } from 'panel/features/sso/api/model';
import intl from 'panel/common/intl';
import { Button } from 'panel/common/ui/Button';

import s from './RememberedDevices.module.pcss';

export const RememberedDevices = () => {
    const [devices, setDevices] = createSignal<SSODevice[]>();
    const [error, setError] = createSignal(false);
    const [busy, setBusy] = createSignal(false);
    let disposed = false;
    onCleanup(() => {
        disposed = true;
    });

    const load = async () => {
        setBusy(true);
        setError(false);
        try {
            const options = { credentials: 'same-origin' as const, skipAuthRedirect: true };
            const result = await getSSODevices(options);
            if (!disposed) setDevices(result);
        } catch (cause) {
            if (!disposed && !(cause instanceof ApiError && cause.status === 401)) setError(true);
        } finally {
            if (!disposed) setBusy(false);
        }
    };

    onMount(async () => {
        try {
            const config = await getAuthConfig();
            if (!disposed && config.sso_enabled) await load();
        } catch {
            // Local-only installations do not need the remembered-device panel.
        }
    });

    const revoke = async (device: SSODevice) => {
        setBusy(true);
        setError(false);
        try {
            await revokeSSODevice({ id: device.id });
            if (disposed) return;
            if (device.current) {
                window.location.replace(new URL('login.html', window.location.href).href);
            } else {
                await load();
            }
        } catch {
            if (!disposed) setError(true);
        } finally {
            if (!disposed) setBusy(false);
        }
    };

    return (
        <Show when={devices() !== undefined || error()}>
            <section class={s.section}>
                <h2>{intl.getMessage('sso_devices')}</h2>
                <Show when={error()}>
                    <p role="alert">{intl.getMessage('sso_devices_error')}</p>
                </Show>
                <ul class={s.devices}>
                    <For each={devices()}>
                        {(device) => (
                            <li class={s.device}>
                                <div class={s.details}>
                                    <p>{device.user_agent}</p>
                                    <Show when={device.current}>
                                        <strong>{intl.getMessage('sso_devices_current')}</strong>
                                    </Show>
                                    <p>
                                        {intl.getMessage('sso_devices_expiry', {
                                            date: new Date(device.expires).toLocaleString(),
                                        })}
                                    </p>
                                </div>
                                <Button
                                    variant="secondary-danger"
                                    disabled={busy()}
                                    onClick={() => revoke(device)}
                                >
                                    {intl.getMessage('sso_devices_revoke')}
                                </Button>
                            </li>
                        )}
                    </For>
                </ul>
                <Button variant="secondary" disabled={busy()} onClick={load}>
                    {intl.getMessage('sso_devices_refresh')}
                </Button>
            </section>
        </Show>
    );
};
