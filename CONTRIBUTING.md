## Contributing

When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.
- If you have questions, please ask them first in the mailing list john-users at lists.openwall.com;
- Use GitHub issues to keep track of ideas, enhancements, tasks, and bugs. NEVER as a support forum;

## Bug Reports

Try to be clear about your environment and what you are doing. If possible, share a sample hash or file that can be used to reproduce.

## Source Code Style

Please refer to `doc/README.coding-style` for information on the subject.

For Jumbo, The maintainer recommends to format code using the following commands:
```
$ indent -kr -i4 -ts4 -nlp -nbbo -ncs -l119 -lc119 -bad -il0
$ astyle --style=kr -t4 -U -H -p -xC119 -c -k3 -z2
```

## License

John the Ripper is released under GNU GPL v2 "or later", with portions also available under more relaxed terms.

Solar Designer's current preference is that new code contributions be licensed under very liberal terms:
```
/*
 * This software is Copyright (c) YEAR YOUR NAME <your at e-mail.address>,<br>
 * and it is hereby released to the general public under the following terms:<br>
 * Redistribution and use in source and binary forms, with or without<br>
 * modification, are permitted.<br>
 */
```
This is a heavily cut-down “BSD license”. You may also include the warranty disclaimer.

## Other sources of information
For various tips and tricks, see also [GitHub wiki](https://github.com/openwall/john/wiki/Assorted-development-notes) and [Openwall's wiki](https://openwall.info/wiki/john)
