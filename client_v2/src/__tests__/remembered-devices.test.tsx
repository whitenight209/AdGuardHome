import { render, screen, waitFor, fireEvent } from '@solidjs/testing-library';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAuthConfig, getSSODevices, revokeSSODevice } from 'panel/features/sso/api/generated';
import { ApiError } from 'panel/api/customFetch';
import { RememberedDevices } from 'panel/features/sso/RememberedDevices';
import { copy } from 'panel/__tests__/helpers/copy';

vi.mock('panel/features/sso/api/generated', () => ({
    getAuthConfig: vi.fn(),
    getSSODevices: vi.fn(),
    revokeSSODevice: vi.fn(),
}));
vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

const originalLocation = Object.getOwnPropertyDescriptor(window, 'location')!;
const device = {
    id: 'a'.repeat(32),
    user_agent: 'Fixture browser',
    current: false,
    created: '2026-01-01T00:00:00Z',
    last_used: '2026-01-01T00:00:00Z',
    expires: '2026-07-01T00:00:00Z',
};

beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getAuthConfig).mockResolvedValue({ sso_enabled: true, local_login_enabled: true });
    vi.mocked(getSSODevices).mockResolvedValue([device]);
    vi.mocked(revokeSSODevice).mockResolvedValue(undefined);
});

afterEach(() => Object.defineProperty(window, 'location', originalLocation));

describe('remembered devices', () => {
    it('lists devices and marks the current device', async () => {
        vi.mocked(getSSODevices).mockResolvedValue([{ ...device, current: true }]);
        render(() => <RememberedDevices />);
        expect(await screen.findByRole('heading', { name: copy('sso_devices') })).toBeVisible();
        expect(screen.getByText(device.user_agent)).toBeVisible();
        expect(screen.getByText(copy('sso_devices_current'))).toBeVisible();
    });

    it('does not load devices when SSO is disabled', async () => {
        vi.mocked(getAuthConfig).mockResolvedValue({
            sso_enabled: false,
            local_login_enabled: true,
        });
        render(() => <RememberedDevices />);
        await waitFor(() => expect(getAuthConfig).toHaveBeenCalledOnce());
        expect(getSSODevices).not.toHaveBeenCalled();
        expect(screen.queryByRole('heading')).toBeNull();
    });

    it('keeps local-password users signed in when the SSO-only endpoint denies access', async () => {
        vi.mocked(getSSODevices).mockRejectedValue(new ApiError('not an SSO session', 401));
        render(() => <RememberedDevices />);
        await waitFor(() => expect(getSSODevices).toHaveBeenCalledOnce());
        expect(getSSODevices).toHaveBeenCalledWith(
            expect.objectContaining({ skipAuthRedirect: true }),
        );
        expect(screen.queryByRole('alert')).toBeNull();
    });

    it('revokes another device and reloads the list', async () => {
        vi.mocked(getSSODevices).mockResolvedValueOnce([device]).mockResolvedValue([]);
        render(() => <RememberedDevices />);
        fireEvent.click(await screen.findByRole('button', { name: copy('sso_devices_revoke') }));
        await waitFor(() => expect(revokeSSODevice).toHaveBeenCalledWith({ id: device.id }));
        await waitFor(() => expect(screen.queryByText(device.user_agent)).toBeNull());
    });

    it('leaves the app when the current device is revoked', async () => {
        const replace = vi.fn();
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: { href: 'https://dns.example.com/adguard/#/settings', replace },
        });
        vi.mocked(getSSODevices).mockResolvedValue([{ ...device, current: true }]);
        render(() => <RememberedDevices />);
        fireEvent.click(await screen.findByRole('button', { name: copy('sso_devices_revoke') }));
        await waitFor(() =>
            expect(replace).toHaveBeenCalledWith('https://dns.example.com/adguard/login.html'),
        );
    });

    it('shows a recoverable error when revocation fails', async () => {
        vi.mocked(revokeSSODevice).mockRejectedValue(new Error('offline'));
        render(() => <RememberedDevices />);
        fireEvent.click(await screen.findByRole('button', { name: copy('sso_devices_revoke') }));
        expect(await screen.findByRole('alert')).toHaveTextContent(copy('sso_devices_error'));
        expect(screen.getByText(device.user_agent)).toBeVisible();
    });

    it('does not update state after the settings panel is closed', async () => {
        let resolve!: (value: (typeof device)[]) => void;
        vi.mocked(getSSODevices).mockReturnValue(
            new Promise((done) => {
                resolve = done;
            }),
        );
        const view = render(() => <RememberedDevices />);
        await waitFor(() => expect(getSSODevices).toHaveBeenCalledOnce());
        view.unmount();
        resolve([device]);
        await Promise.resolve();
        expect(screen.queryByRole('heading')).toBeNull();
    });
});
