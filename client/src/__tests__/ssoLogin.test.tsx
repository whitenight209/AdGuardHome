import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import apiClient from '../api/Api';
import { SsoLogin } from '../features/sso/SsoLogin';

vi.mock('../api/Api', () => ({ default: { makeRequest: vi.fn() } }));
vi.mock('react-i18next', () => ({
    useTranslation: () => ({ t: (key: string) => key }),
}));

let container: HTMLDivElement;
beforeEach(() => {
    vi.resetAllMocks();
    window.history.replaceState({}, '', '/login.html');
    container = document.createElement('div');
    document.body.appendChild(container);
});
afterEach(() => {
    ReactDOM.unmountComponentAtNode(container);
    container.remove();
});

it('offers the configured provider without changing the current page', async () => {
    vi.mocked(apiClient.makeRequest).mockResolvedValue({
        sso_enabled: true,
        sso_display_name: 'Google',
        sso_start_url: '/control/sso/oidc/start',
    });
    await act(async () => { ReactDOM.render(<SsoLogin><input aria-label="local-user" /></SsoLogin>, container); });
    expect(container.querySelector('a')?.getAttribute('href')).toBe('/control/sso/oidc/start');
    expect(window.location.pathname).toBe('/login.html');
    expect(container.querySelector('input')).toBeNull();
    expect(container.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
});

it('hides SSO when disabled', async () => {
    vi.mocked(apiClient.makeRequest).mockResolvedValue({ sso_enabled: false });
    await act(async () => { ReactDOM.render(<SsoLogin><input aria-label="local-user" /></SsoLogin>, container); });
    expect(container.querySelector('a')).toBeNull();
    expect(container.querySelector('input')).not.toBeNull();
});

it('shows sanitized errors when the options request fails', async () => {
    vi.mocked(apiClient.makeRequest).mockRejectedValue(new Error('private-detail'));
    await act(async () => { ReactDOM.render(<SsoLogin><input aria-label="local-user" /></SsoLogin>, container); });
    expect(container.querySelector('[role="alert"]')?.textContent).toBe('sso_error');
    expect(container.textContent).not.toContain('private-detail');
    expect(container.querySelector('input')).not.toBeNull();
});

it('keeps the provider link inside a proxy prefix', async () => {
    window.history.replaceState({}, '', '/vault/login.html');
    vi.mocked(apiClient.makeRequest).mockResolvedValue({
        sso_enabled: true,
        sso_start_url: '/vault/control/sso/oidc/start',
    });
    await act(async () => { ReactDOM.render(<SsoLogin><input aria-label="local-user" /></SsoLogin>, container); });
    expect(container.querySelector('a')?.getAttribute('href')).toBe('/vault/control/sso/oidc/start');
});
