import { cleanup, fireEvent, render, screen, waitFor } from '@solidjs/testing-library';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAuthConfig, refreshSSO } from 'panel/features/sso/api/generated';
import { SsoLogin } from 'panel/features/sso/SsoLogin';

vi.mock('panel/features/sso/api/generated', () => ({
    getAuthConfig: vi.fn(),
    refreshSSO: vi.fn().mockRejectedValue(new Error('no device')),
}));
vi.mock('panel/common/intl', () => ({
    default: {
        getMessage: (key: string, values?: { provider: string }) =>
            values ? `${key} ${values.provider}` : key,
    },
}));

beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(refreshSSO).mockRejectedValue(new Error('no remembered device'));
    window.history.replaceState({}, '', '/login.html');
});
afterEach(cleanup);

describe('SSO login', () => {
    it('shows an accessible provider link after loading', async () => {
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: true,
            sso_display_name: 'Google',
            sso_start_url: '/control/sso/oidc/start',
        });
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        expect(screen.getByText('sso_loading')).toBeTruthy();
        expect(screen.queryByRole('textbox')).toBeNull();
        const link = await screen.findByRole('link', { name: 'sso_sign_in Google' });
        expect(link.getAttribute('href')).toBe('/control/sso/oidc/start');
        expect(window.location.pathname).toBe('/login.html');
        expect(screen.queryByRole('textbox')).toBeNull();
        expect(link.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
    });

    it('opts into remembered login only when the checkbox is checked', async () => {
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: true,
            sso_display_name: 'Google',
            sso_start_url: '/control/sso/oidc/start',
        });
        render(() => <SsoLogin />);
        const choice = await screen.findByRole('checkbox', { name: 'sso_remember_device' });
        const link = screen.getByRole('link', { name: 'sso_sign_in Google' });
        expect(choice).not.toBeChecked();
        expect(link).toHaveAttribute('href', '/control/sso/oidc/start');
        fireEvent.click(choice);
        expect(link).toHaveAttribute('href', '/control/sso/oidc/start?remember=1');
        fireEvent.click(choice);
        expect(link).toHaveAttribute('href', '/control/sso/oidc/start');
    });

    it('restores a remembered session before asking the user to sign in again', async () => {
        const original = Object.getOwnPropertyDescriptor(window, 'location')!;
        const replace = vi.fn();
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: { href: 'https://dns.example.com/adguard/login.html', search: '', replace },
        });
        try {
            vi.mocked(getAuthConfig).mockResolvedValue({
                local_login_enabled: true,
                sso_enabled: true,
                sso_display_name: 'Google',
                sso_start_url: '/adguard/control/sso/oidc/start',
            });
            vi.mocked(refreshSSO).mockResolvedValue(undefined);
            render(() => <SsoLogin />);
            await waitFor(() =>
                expect(replace).toHaveBeenCalledWith('https://dns.example.com/adguard/'),
            );
        } finally {
            Object.defineProperty(window, 'location', original);
        }
    });

    it('keeps the provider link within the current proxy prefix', async () => {
        window.history.replaceState({}, '', '/vault/login.html');
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: true,
            sso_display_name: 'Google',
            sso_start_url: '/vault/control/sso/oidc/start',
        });
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        const link = await screen.findByRole('link', { name: 'sso_sign_in Google' });
        expect(link.getAttribute('href')).toBe('/vault/control/sso/oidc/start');
    });

    it('does not offer SSO when disabled', async () => {
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: false,
        });
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        await waitFor(() => expect(screen.queryByText('sso_loading')).toBeNull());
        expect(screen.queryByRole('link')).toBeNull();
        expect(screen.queryByRole('textbox')).toBeTruthy();
    });

    it('rejects a remote start URL', async () => {
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: true,
            sso_start_url: 'https://attacker.example/',
        });
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        await waitFor(() => expect(screen.queryByText('sso_loading')).toBeNull());
        expect(screen.queryByRole('link')).toBeNull();
    });

    it('shows a recoverable error when options cannot load', async () => {
        vi.mocked(getAuthConfig).mockRejectedValue(new Error('offline'));
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        expect(await screen.findByRole('alert')).toHaveTextContent('sso_error');
        expect(screen.getByRole('textbox')).toBeTruthy();
    });

    it('keeps local login hidden after an SSO callback failure', async () => {
        window.history.replaceState({}, '', '/login.html?sso_error=failed');
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: true,
            sso_display_name: 'Google',
            sso_start_url: '/control/sso/oidc/start',
        });
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        await screen.findByRole('link');
        expect(screen.getByRole('alert')).toBeTruthy();
        expect(screen.queryByRole('textbox')).toBeNull();
    });

    it('does not reflect arbitrary callback error text', async () => {
        window.history.replaceState({}, '', '/login.html?sso_error=untrusted-text');
        vi.mocked(getAuthConfig).mockResolvedValue({
            local_login_enabled: true,
            sso_enabled: false,
        });
        render(() => (
            <SsoLogin>
                <input aria-label="local-user" />
            </SsoLogin>
        ));
        expect(screen.getByRole('alert')).toHaveTextContent('sso_error');
        expect(screen.queryByText('untrusted-text')).toBeNull();
        await waitFor(() => expect(screen.queryByText('sso_loading')).toBeNull());
    });
});
