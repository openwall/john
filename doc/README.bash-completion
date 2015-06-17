	Enabling bash completion for John the Ripper

To enable bash completion for john and unique for all users, just use

make bash-completion

You need administrative privileges for this make target, because
the script john.bash_completion will be copied to /etc/bash_completion.d/.

To enable bash completion just for your user, it is enough to source
the bash completion script in your  ~/.bashrc
To to this, add the following line to your ~/.bashrc file:
. <path_to_john's_config_directory>/john.bash_completion

To just enable bash completion for john and unique temporarily,
just execute the following command in your current session:
$ . <path_to_john's_config_directory>/john.bash_completion

(The $ just indicates the command prompt, it is not part of the command.)

If you build different john versions, say a default (non-omp) version
named john, and an omp-enabled version named john-omp, you can enable
the same bash completion logic for the john-omp binary by adding this line
to your ~./bashrc file:
complete -F _john john-omp


	Prerequisites

The bash completion for john requires bash version >= 4,
and extended pattern matching features enabled.
If the command
	shopt -p extglob
prints
	shopt -s extglob
then the extended pattern matching features are enabled.
If this command
prints
	shopt -u extglob
then they are disabled.


	Features

The bash completion for unique does nothing for a non-jumbo build.
For a jumbo build, it supports completion for the command line options
which only exist for the jumbo version.


The bash completion for john supports file name completion for
password (hash) files.
It also supports completion for the command line options.


Abbreviated command line options are completed to their long form,
with two leading '-' characters.
For options with a mandatory value, the completion also adds the '='
character.


	Examples

$ ./john -w[tab]
results in completion to
$ ./john --wordlist=

$ ./john --wordlist=[tab][tab]
will list all file names in the current directory as possible completions.


$ ./john -fo[tab]

$ john --f[tab]
for an official, non-jumbo john version 1.7.8 results in completion to
$ john --format=

$ john --format=[tab][tab]
for the official john version 1.7.8 will list all the supported formats
as possible completions:
AFS    BF     BSDI   crypt  DES    LM     MD5

$ john --format=D[tab]
will be completed to
$ john --format=DES


For a jumbo version, e.g. 1.7.9-jumbo-5,
$ ./john -f[tab]
will become
$ ./john --f
The reason is that --format is not the only option starting with --f.

For this version,
$ ./john --f[tab][tab]
will list all possible completions like this:

$ ./john --f
--field-separator-char=  --fix-state-delay=       --format=

$ ./john --fo[tab]
will become
$ ./john --format=

$ ./john --format=[tab]tab]
will list all available formats of this version as possible completions:

$ ./john --format=
afs           lm            netntlm       raw-sha
bf            lotus5        netntlmv2     raw-sha1
bfegg         md4-gen       nsldap        raw-sha224
bsdi          md5           nt            raw-sha256
crc32         md5ns         nt2           raw-sha384
crypt         mediawiki     oracle        raw-sha512
des           mscash        oracle11      salted-sha1
dmd5          mscash2       pdf           sapb
dominosec     mschapv2      phpass-md5    sapg
dummy         mskrb5        phps          sha1-gen
dynamic       mssql         pix-md5       ssh
epi           mssql05       pkzip         sybasease
hdaa          mysql         po            trip
hmac-md5      mysql-fast    rar           xsha
hmailserver   mysql-sha1    raw-md4       xsha512
ipb2          nethalflm     raw-md5       zip
krb4          netlm         raw-md5thick
krb5          netlmv2       raw-md5u

$ ./john --format=a[tab]
will become
$ ./john --format=afs

To get possible completions for values of an option, it is not required
to use the full name of that option.
Instead, it is possible to start the option name with just one '-' character
instead of two.

It is also possible to use the ':' character (colon) instead of the '='
character (equal sign) to separate option name and value, because john
also supports this character as a separator between option and value.
(The completion logic for options with a colon as a separator depends on
the value of the environment variable COMP_WORDBREAKS.
The default logic explained here assumes that COMP_WORDBREAKS contains
the colon. The logic used when COMP_WORDBREAKS doen't contain the colon
is mentioned in the last chapter ("Config variables") of this document.)

Furthermore, the option name can be abbreviated, provided it is not ambiguous.

E.g., for an official, non-jumbo john version 1.7.8 bash completion will list
all supported hash formats as possible completions, if the  [tab] key
is pressed twice at the end of the command line:
$ john -f:
$ john -f=
$ john --f:
$ john --f=
$ john -fo:
$ john -fo=
$ john --fo:
$ john --fo=
...

For a jumbo build, the first 4 examples will not work, because the option name
is ambiguous.
A jumbo version also has the options --field-separator-char= and
--fix-state-delay=, so at least the first two letters of the option name
must be specified.

If future john versions get new options with names beginning with --fo,
even more letters need to be specified.

Similarly, for an official john version 1.7.8 build,
$ john -f:c[tab]
would become
$ john -f:crypt

And
$ john -fo=D[tab]
will become
$ john -fo=DES

That means, only the value will be completed, the option name and the separator
between option name and value remain unchanged.
This is OK, because john also supports using an abbreviated option name,
as long as it is not ambiguous.


If the john version supports the --list=hidden-options option, then the
hidden options (not mentioned in john's usage output) are also considered as
valid completions for option names.


	Special completion for certain options

	--format=

As mentioned above in the general description of the completion logic,
the completion logic considers all the supported formats, as listed
in john's usage output.
For the jumbo version, there is a special handling for the dynamic formats
(see the files DYNAMIC and DYNAMIC_SCRIPTING for more information).

$ ./john --format=dy[tab]
will become
$ ./john --format=dynamic

$ ./john --format=dynamic[tab]
will become
$ ./john --format=dynamic_

$ ./john --format=dynamic_[tab][tab]
will list all available dynamic formats, like this:

$ ./john --format=dynamic_
dynamic_0     dynamic_1006  dynamic_15    dynamic_22    dynamic_3
dynamic_1     dynamic_1007  dynamic_16    dynamic_23    dynamic_4
dynamic_10    dynamic_1008  dynamic_17    dynamic_24    dynamic_5
dynamic_1001  dynamic_1009  dynamic_18    dynamic_25    dynamic_6
dynamic_1002  dynamic_11    dynamic_19    dynamic_26    dynamic_7
dynamic_1003  dynamic_12    dynamic_2     dynamic_27    dynamic_8
dynamic_1004  dynamic_13    dynamic_20    dynamic_28    dynamic_9
dynamic_1005  dynamic_14    dynamic_21    dynamic_29


	--rules and --single

For official john version of john which don't support optional values
for --rules and --single, completion will just add a trailing space
at the end of the command line, so that the user can continue typing
the next word (e.g., an option or file name) on the command line.

Jumbo versions, however, support an optional value, as indicated by
john's usage output (--rules[=SECTION] and --single[=SECTION]).

For a jumbo version, the completion logic for options --rules
and --single depends on the contents of the environment variable
__john_completion, see the last chapter ("Config variables")
of this document.
The default logic works like this:

$ ./john --rules[tab][tab]
will list possible completions like this:
$ ./john --rules
--rules           --rules=single
--rules=NT        --rules=wordlist

In the above example, the upper case section name NT indicates that
the list of rules sections is a hard coded list of sections known to
exist in (almost) every john version.


For more recent versions which support the --list=rules option,
the list of section names will be obtained by interpreting the config
file (default john.conf or john.ini, unless another config file is
specified on the command line, see john's option --config=...)

In this case, the list of possible completions looks like this:

$ ./john --rules
--rules           --rules=single
--rules=nt        --rules=wordlist

(Please note that in this case all section names are lower case,
because john doesn't distinguish upper and lower case characters
in section names.)

If you add a section [List.Rules:My_Test] to john.conf,
$ ./john --rules[tab][tab]
will list possible completions like this:

$ ./john --rules
--rules           --rules=nt        --rules=wordlist
--rules=my_test   --rules=single

Since --single can use the same sections,
$ ./john --single[tab][tab]
will list possible completions like this:
$ ./john --single
--single           --single=nt        --single=wordlist
--single=my_test   --single=single

If you use another config file name my.conf with these rules sections
[List.Rules:some_rules]
[List.Rules:more_rules]
you can specify this config file on the command line.

$ ./john --conf=my.conf --rules[tab][tab]
will list possible completions like this:

$ ./john --conf=my.conf --rules
--rules             --rules=some_rules
--rules=more_rules

The same possible completions are listed if you switch the sequence
of the options on the command line, place the cursor immediately after
the word "--rules", and press the  [tab] key twice.

$ ./john --rules[tab][tab] --config=my.conf
will list possible completions like this:
$ ./john --rules --config=my.conf
--rules             --rules=some_rules
--rules=more_rules

$ ./john --rules=s[tab] --config=my.conf
will become
$ ./john --rules=some_rules --config=my.conf


	--incremental

The option --incremental can be used with and without a value.
Possible values are the Incremental section names defined in john.conf
(or another config file specified with --config=..., see the description
of the completion logic for --rules and --single).

The completion logic depends on the contents of the environment variable
__john_completion, see the last chapter ("Config variables")
of this document.
The default logic works like this:

If the john version doesn't support the --list=inc-modes option,
possible completions will be listed based on the john version and
incremental mode sections known to exist in (almost) all john versions:

$ ./john --incremental[tab][tab]
will list possible completions like this:

$ ./john --incremental
--incremental         --incremental=Alnum   --incremental=Digits
--incremental=All     --incremental=Alpha   --incremental=LanMan

If the john version supports --list=inc-modes, the possible completions
will be obtained by interpreting the config file (default john.conf or
john.ini, unless another config file is specified on the command line,
see john's option --config=...).

In this case, the possible completions listed might look like this:

$ ./john --incremental
--incremental          --incremental=all7     --incremental=digits
--incremental=all      --incremental=all8     --incremental=digits8
--incremental=all15    --incremental=alnum    --incremental=lanman
--incremental=all6     --incremental=alpha

$ ./john --incremental=l[tab]
will become
$ ./john --incremental=lanman

If all the incremental mode names are listed in lower case, you can also
use
$ ./john --incremental=L[tab]
This will become
$ ./john --incremental=lanman
as well.


	--external

If the john version supports the --list=externals option, the possible
completions will be obtained by interpreting the config file (default john.conf or
john.ini, unless another config file is specified on the command line,
see john's option --config=...).

In this case, the possible completions listed might look like this:

$ ./john --external=
appendluhn                filter_alnum
atleast1-generic          filter_alpha
atleast1-simple           filter_digits
autoabort                 filter_lanman
autostatus                filter_no_cap_or_symbols
datetime                  keyboard
double                    knownforce
double10                  lanman
double10_alnum            parallel1_2
double_all                parallel2_2
double_alnum              policy
dumb16                    repeats
dumb32                    strip
dumbforce                 subsets

(A config file specified on the command line will be taken into account when
determining the possible completions, see the description of the completion
for the options --incremental, --rules and --single.)


If the john version doesn't support the --list=externals option, the possible
completions are hard coded, depending on the john version you try to run.
In this case, the possible completions listed might look like this:

$ ./john --external=
AppendLuhn        DateTime          Filter_Digits     Parallel
AtLeast1-Generic  Double            Filter_LanMan     Policy
AtLeast1-Simple   DumbForce         Keyboard          Repeats
AutoAbort         Filter_Alnum      KnownForce        Strip
AutoStatus        Filter_Alpha      LanMan            Subsets

(john version 1.7.9-jumbo-5)

For john version 1.7.8, the list will look like this:

$ john --external=
AppendLuhn        DumbForce         Keyboard          Repeats
AtLeast1-Generic  Filter_Alnum      KnownForce        Strip
AtLeast1-Simple   Filter_Alpha      LanMan            Subsets
DateTime          Filter_Digits     Parallel
Double            Filter_LanMan     Policy

$ john --external=Da[tab]
will become
$ john --external=DateTime


	--make-charset=

Completion will list names of .chr files and directories in the
current directory for completion.

$ ./john --make-charset=[tab][tab]
might list completions like this:

$ ./john --make-charset=
all.chr     alpha.chr   lanman.chr
alnum.chr   digits.chr  subdir/

Please note that an existing file will be overwritten
when executing the command. So please be careful!


	--config=

If the john version supports the --config= option, possible completions
are all directory names and file names with the extensions .conf and .ini.
(Files with extensions .CONF, .INI, .Conf, .Ini will also be considered,
because the search is not case sensitive.)


	--pot=

If the john version supports the --pot= options, possible completions
are all directory names and file names with the extension .pot.
(The search is not case sensitive, so file names with extensions .POT
and .Pot will also be considered during completion.)


	--restore and --status

The options --restore and --status can be used without a value (in this case,
the session name will be "john") or with a value (session name).

Since names of john sessions are possible completions,
the possible completions are derived from .rec file names.
In addition, names of sub directories are also considered, since .rec files
might be located in a sub directory.
(For --restore=, only names of sessions not currently running should be
considered. This is not yet implemented.)

The completion logic for these options depends on the contents of the
environment variable __john_completion, see the last chapter
("Config variables") of this document.

The default logic works like this:

$ ls *.rec
john.rec  test1.rec

$ ls -d subdir/ testdata/
subdir/  testdata/

$ john --status[tab][tab]
will list possible completions like this:

$ john --status
--status           --status=subdir    --status=testdata
--status=john      --status=test1

A similar list of completions for --restore:
$ john --restore
--restore           --restore=subdir    --restore=testdata
--restore=john      --restore=test1

$ john --restore=[tab][tab]
will list possible completions like this:

$ john --restore=
john      subdir/   test1     testdata/

$ john --restore=t[tab]
will become
$ john --restore=test

$ john --restore=test[tab][tab]
will list possible completions like this:

$ john --restore=test
test1     testdata/



	Config variables

	COMP_WORDBREAKS

You shouldn't change the contents of this variable unless you really know
what you are doing!
Usually, you should leave this value unchanged.
(You never know which other completion scripts depend on the
contents of COMP_WORDBREAKS.)

Use the following command to show the contents of COMP_WORDBREAKS:

$ echo "$COMP_WORDBREAKS"

"'><=;|&(:

You can also use:

$ echo $COMP_WORDBREAKS
"'><=;|&(:

(Note that with the second command (without quotes), you'll not see that
the variable also contains a line feed character.)


The completion logic implemented for john depends on whether or not
COMP_WORDBREAKS contains the colon character (':').

If COMP_WORDBREAKS doesn't contain the colon, this is the completion logic:

$ john -opt:val[tab]
becomes
$ john -opt=val

$ john -opt:[tab]
becomes
$ john -opt=

This means, for an option (beginning with at least one '-' char) followed
by a colon (':') as a delimiter, possibly followed by other characters
(except '=' or ':') the colon will be replaced by an equal sign.
Pressing the  [tab] key again will then invoke the normal completion logic
as described throughout this document.


To remove the colon from COMP_WORDBREAKS, use:
$ COMP_WORDBREAKS="${COMP_WORDBREAKS//:/}"

To add the colon to COMP_WORDBREAKS, use:
$ COMP_WORDBREAKS="${COMP_WORDBREAKS}:"

As always, the $ indicates the command prompt, and it is not part
of the command.

If you want to add this command to your ~/.bashrc, you'll have to use
COMP_WORDBREAKS="${COMP_WORDBREAKS//:/}"
or
COMP_WORDBREAKS="${COMP_WORDBREAKS}:"


	__john_completion

The value of the variable __john_completion is used to adjust the completion
logic for options that can be used either with a value or without a value.

These options are
--restore
--status
--incremental

Furthermore, in jumbo versions, these options can be used with or
without a value:
--rules
--single
--show

(There are other options that can be used with or without a value.
But the completion logic for those other options is more or less limited
to a usage hint, and therefore doesn't depend on the value of the variable
__john_completion.)


For the option --show, the completion logic will always work like this:
$ ./john -sho[tab]
becomes
$ ./john --show

The cursor is positioned exactly after the "w", no trailing space is added
in this case.
(For an option that doesn't allow any values, a trailing space would be added.)


If __john_completion is not defined or has any other value than 2,
the default completion logic is used.
It works like this:

$ ./john --show[tab]
just lists the possible completions like this:

$ ./john --show
--show       --show=

To add a file name, you'll first have to add the space, to separate
the file name from the option name.
To further expand the option instead, you'll have to type the '='
(equal sign).

If __john_completion has the value 2, the following alternative completion
logic is implemented for options that can be used with or without a value.

$ ./john --show[tab]
will become
$ ./john --show=


Completion of --option= does not depend on the value of  __john_completion.

$ ./john --show=[tab][tab]
left   types

Since there is just one possible value for --show=l,
$ ./john --show=l[tab]
will become
$ ./john --show=left

(A space character will be added after "--show=left".)

So, if you prefer to hit the [tab] key instead of typing '=',
you might want to add this line to your ~/.bashrc file:
__john_completion=2

