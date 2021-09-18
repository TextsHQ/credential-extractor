const {
    loginCredentials,
    decryptCredential,
} = require('../ce.node');

// TODO: Generic-ify Credential once non-browser sources are added
export interface Credential {
    readonly browser: string;

    readonly url: string;

    readonly username?: string;

    readonly encrypted_password: Buffer;

    readonly username_element?: string;

    readonly password_element?: string;
}

export function browserLoginCredentials(url: string): Credential[] {
    return loginCredentials(url);
}

export function browserDecryptCredential(credential: Credential): string {
    return decryptCredential(credential);
}

