const {
    searchLoginCredentials,
} = require('../index.node');

export interface Credential {
    url: string;

    username: string;

    password: string;
}

export function searchBrowserLoginCredentials(url: string): Credential[] {
    return searchLoginCredentials(url);
}

