const { browserLoginCredentials, browserDecryptCredential } = require('../dist');

test('Browser credentials fetch & decryption', () => {
    let credentials = browserLoginCredentials();

    console.log(`Stored credentials across browsers: ${credentials.length}`);
    console.log('Decrypting credential: ', credentials[0]);
    console.log(browserDecryptCredential(credentials[0]));
});
