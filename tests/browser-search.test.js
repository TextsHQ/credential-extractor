const { browserLoginCredentials } = require('../dist');

test('URL credentials search', () => {
    console.log(browserLoginCredentials());
});
