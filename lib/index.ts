const {
    loginCredentials,
} = require('../index.node');

export interface Credential {
    url: string;

    username: string;

    password: string;
}

export function browserLoginCredentials(): Credential[] {
    return loginCredentials();
}

