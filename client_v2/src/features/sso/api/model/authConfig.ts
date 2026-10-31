export interface AuthConfig {
    local_login_enabled: boolean;
    sso_enabled: boolean;
    sso_display_name?: string;
    sso_start_url?: string;
}
