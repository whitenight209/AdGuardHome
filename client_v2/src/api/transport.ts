export type RequestTransport = (url: string, options: RequestInit) => Promise<Response>;

const nativeTransport: RequestTransport = (url, options) => fetch(url, options);
let transport = nativeTransport;

// Optional application extensions configure transport during startup. The
// common API client has no dependency on an extension's routes or policies.
export const setRequestTransport = (next: RequestTransport = nativeTransport): void => {
    transport = next;
};

export const sendRequest: RequestTransport = (url, options) => transport(url, options);
