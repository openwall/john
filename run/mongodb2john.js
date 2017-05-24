/*
 * This software is Copyright (c) 2016 AverageSecurityGuy <stephen at averagesecurityguy.info>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

// https://averagesecurityguy.github.io/2016/04/29/finding-and-exploiting-mongodb/
// Usage: mongo admin mongodb2john.js
//        mongo [hostname]:[port]/[database_name] mongodb2john.js

try {
	cursor = db.system.users.find();
	while ( cursor.hasNext() ) {
		c = cursor.next();
		if (c['credentials']['MONGODB-CR']) {
			print(c['user'] + '-' + c['db'] + ':' + '$mongodb$0$' + c['user'] + '$' + c['credentials']['MONGODB-CR']);
			print(c['user'] + ':' + '$dynamic_1550$' + c['credentials']['MONGODB-CR']);
		}

		if (c['credentials']['SCRAM-SHA-1']) {
			s = c['credentials']['SCRAM-SHA-1'];
			shash = '$scram$' + c['user'] + '$' + s['iterationCount'] + '$' + s['salt'] + '$' + s['storedKey'];
			print(c['user'] + '-' + c['db'] + ':' + shash);
		}
	}
} catch(err) {}
