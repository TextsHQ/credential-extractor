const { browserLoginCredentials, browserDecryptCredential } = require('../dist');

test('Browser credentials fetch & decryption', () => {
    const URL = 'spotify.com';

    let credentials = browserLoginCredentials(URL);

    console.log(`Stored credentials like: ${URL}`);

    for (const cred of credentials) {
        if (cred.passwordEncrypted) {
            cred.password = browserDecryptCredential(cred);
        }

        console.table(cred);
    }
});
