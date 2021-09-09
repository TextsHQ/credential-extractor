const { browserLoginCredentials, browserDecryptCredential } = require('../dist');

test('Browser credentials fetch & decryption', () => {
    const URL = 'https://twitter.com';

    let credentials = browserLoginCredentials(URL);

    console.log(`Stored credentials like: ${URL}%`);
    console.log('Decrypting credential: ', credentials[0]);
    console.log(browserDecryptCredential(credentials[0]));
});
