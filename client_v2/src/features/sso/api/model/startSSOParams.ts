import type { StartSSORemember } from './startSSORemember';

export type StartSSOParams = {
    /**
     * Opt into a remembered device for this login.
     */
    remember?: StartSSORemember;
};
