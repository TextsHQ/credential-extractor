const { searchBrowserLoginCredentials } = require('../dist');

test('URL credentials search', () => {
    console.log(searchBrowserLoginCredentials('https://mail.google.com/mail/u/0/'));
});
