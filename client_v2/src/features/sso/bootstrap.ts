import { setRequestTransport } from 'panel/api/transport';
import { rememberedTransport } from './api/transport';

// Run before every HTML entry point, without patching window.fetch globally.
setRequestTransport(rememberedTransport);
