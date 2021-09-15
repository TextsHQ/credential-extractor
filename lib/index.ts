const {
    loginCredentials,
    decryptCredential,
} = require('../ce.node');

export interface Credential {
    readonly browser: string;

    readonly url: string;

    readonly username: string;

    readonly encrypted_password: Buffer;
}

export function browserLoginCredentials(url: string): Credential[] {
    return loginCredentials(url);
}

export function browserDecryptCredential(credential: Credential): string {
    return decryptCredential(credential);
}

