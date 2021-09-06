const {
    loginCredentials,
    decryptCredential,
} = require('../index.node');

export interface Credential {
    readonly browser: string;

    readonly url: string;

    readonly username: string;

    readonly encrypted_password: Buffer;
}

export function browserLoginCredentials(): Credential[] {
    return loginCredentials();
}

export function browserDecryptCredential(credential: Credential): string {
    return decryptCredential(credential);
}

