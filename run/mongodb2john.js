/*
 * This software is Copyright (c) 2016 AverageSecurityGuy <stephen at averagesecurityguy.info>,
 * Copyright (c) 2025 Dhiru Kholia <dhiru at openwall.com> and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/*

admin> db.system.users.find()
[
  {
    _id: 'admin.admin',
    userId: UUID('756ee40b-866c-4f3b-8972-8b5f45c3328a'),
    user: 'admin',
    db: 'admin',
    credentials: {
      'SCRAM-SHA-1': {
        iterationCount: 10000,
        salt: 'X3yVLbAxujboAefdz8WDzw==',
        storedKey: 'XINfhTxbvQ1GRoLZtFLFU+Hjvw8=',
        serverKey: 'V+NsobMd2BQ8vm0oIDAY4OHuEzc='
      },
      'SCRAM-SHA-256': {
        iterationCount: 15000,
        salt: 'FrhIN9jUgho0r9x1duQM/no4dcvgr/Jp/9Eunw==',
        storedKey: 'VPFmupNQ3CLEq+uysuctCs7eV7SIqGd/mC1WRJl3Zos=',
        serverKey: 'vYDDuo3MdFS8cjfOwpaJHNQGlnUmELobDp0HEq0hnKM='
      }
    },
    roles: [
      { role: 'userAdminAnyDatabase', db: 'admin' },
      { role: 'readWriteAnyDatabase', db: 'admin' }
    ]
  },
  {
    _id: 'test.myTester',
    userId: UUID('bc3d5626-c767-4c5c-b07a-039150a602ca'),
    user: 'myTester',
    db: 'test',
    credentials: {
      'SCRAM-SHA-1': {
        iterationCount: 10000,
        salt: 'TTXOfwOa5/EV30YGuBR7yQ==',
        storedKey: '0+JTOuxBauhqCv3itDLNuOBElzw=',
        serverKey: '4021f5lGSwa9fC+gvtueLOKBcng='
      },
      'SCRAM-SHA-256': {
        iterationCount: 15000,
        salt: 'Vb3xTiskvFJ93OlErvYgBB+xebGc7YiwCCDcow==',
        storedKey: 'WEnOG0hYYtuehBUNQFEtlyy5RV8DNg36Jh6spMZo+bk=',
        serverKey: 'LvLjqZhBZyIRhXBlIStvOfofmluJEVUGonX8sBdPdec='
      }
    },
    roles: [
      { role: 'read', db: 'reporting' },
      { role: 'readWrite', db: 'test' }
    ]
  }
]

*/

// https://averagesecurityguy.github.io/2016/04/29/finding-and-exploiting-mongodb/
// Usage: mongosh admin mongodb2john.js
//        mongosh [hostname]:[port]/[database_name] mongodb2john.js
//        mongosh mongodb://admin:password@zippy.local:27017/admin mongodb2john.js

try {
	// console.log(db.getUsers());
	cursor = db.system.users.find();
	while ( cursor.hasNext() ) {
		c = cursor.next();
		// console.log(c);
		if (c['credentials']['MONGODB-CR']) {
			print(c['user'] + '-' + c['db'] + ':' + '$mongodb$0$' + c['user'] + '$' + c['credentials']['MONGODB-CR']);
			print(c['user'] + ':' + '$dynamic_1550$' + c['credentials']['MONGODB-CR']);
		}

		if (c['credentials']['SCRAM-SHA-1']) {
			s = c['credentials']['SCRAM-SHA-1'];
			shash = '$scram$' + c['user'] + '$' + s['iterationCount'] + '$' + s['salt'] + '$' + s['storedKey'];
			print(c['user'] + '-' + c['db'] + ':' + shash);
		}
		if (c['credentials']['SCRAM-SHA-256']) {
			s = c['credentials']['SCRAM-SHA-256'];
			shash = '$scram-pbkdf2-sha256$' + s['iterationCount'] + '$' + s['salt'] + '$' + s['serverKey'];
			print(c['user'] + '-' + c['db'] + ':' + shash);
		}

	}
} catch(err) {
	console.log(err);
}
