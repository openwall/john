cprepair is a tool that reads br0ken files that may either contain text
accidentally encoded to UTF-8 twice, and/or is a mix of correct UTF-8 and a
legacy codepage - and tries to output fixed data.

Usage:
./cprepair <INFILE >OUTFILE

To see what would be converted, try:
./cprepair -s -d <INFILE

The legacy codepage defaults to CP1252 but can be chosen with -i.

For use on a john.pot file and if you only want to convert stuff after the
first colon, add -p option.

The output is always correct UTF-8 but might not always be a correct conversion,
especially if the input contains a mix of legacy codepage encodings. For strings
like "Müller" or "Стандарт" it is easy (for a human) to guess a correct
encoding but for a string made of random characters of which just one is 8-bit
you can never know.

A very good example use of this tool is fixing the original RockYou dataset.
