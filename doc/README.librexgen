Rexgen.txt - This document describes how to use the rexgen library, to perform
regex expression work within JtR.  Rexgen library is copywrite Jan Starke,
jan.starke@outofbed.org   The regex.c code in JtR by JimF, Spring 2014.

NOTE this support is experimental and may not build at all until tweaked.
The rexgen library is notorious for changing its API between versions,
breaking stuff.  Leave this step out unless you really know that you want
it and are capable of fixing issues.  Last known good version is 2.1.5.

First off, see the section at the bottom of this document about how to obtain
build and install librexgen.

Usage within JtR: --regex[=option=option2=option3]=expression

The current options we have are:
    case      will tell librexgen to do case insensitive work
    alpha     This will use replaceable alphabets.  This can do some REALLY
              fun things, like replace a letter with a word, etc. The alphabet
              will be run to convert the reg-ex AFTER the word has been
              prepared and delivered.  Fun things like f mapping to ph
              or M mapping to |\/| can be done.  Case can also easily be
              done here if the case option is also used. These options
              are stored in the regex_alphabets.conf file in ./run dir
              of JtR.  There are these current alphabets:
              The default (if just =alpha is used). It is an empty
              alphabet, nothing will change.  alpha:case  This is the
              same as using the case option.  alpha:leet  This is a
              simple 1337 (elite) transform, where some common lower
              case letters are changed to numbers.  alpha:leet_case
              is the same leet, but has full case conversion handled.
              alpha:leet2 and alpha_leet2_case are a little stronger
              elite stuff (with and without casing).  alpha:leet3
              and alpha:leet3_case are strong elite, but probably
              overkill as far as password guessing goes. They will
              certainly find more, but there are a LOT of obsure multi-
              letter replacements which likely are not seen in garden
              variety passwords. h -> h H  |-|  ]-[  }-{  (-)  )-(  }{  #
              is one example of alpha:leet3.
              alpha:ascii2nonascii is a alphabet which will convert ascii
              characters into non ascii utf8 characters which 'look'
              similar (i.e. a with grave, umlat, accent, hook, etc)


Currently, rexgen can be used stand alone, OR with wordlist and rules.

The command line switch for stand alone is --regex[=case]=expression
The expression is a stand alone rexex expression.  If the optional
=case is there, then the expression is handled in a case insensitive
manner (case mangling).  So using:  --regex=case=pass  would use these:
PASS
PASs
PaSS
PaSs
pASS
pASs
paSS
paSs
PAsS
PAss
PasS
Pass
pAsS
pAss
pasS
pass

Stand alone usage is not most useful (especially since the rexgen built
command can do this and more).  But it is there more to use as 'testing'
for building expressions (along with using JtR's --stdout).


RexGen in --wordlist mode:

This is more powerful. It addes rexgen logic to each word from the wordlist
to happen AFTER any rules (JtR rules) are applied.  In this mode, all \0 will
be replaced with the current word (from wordlist, with rules applied), and
then all of the regular expressions will be performed on this word.


------------------------------------------------
--- Obtaining, building, installing rexgen.  ---
------------------------------------------------

Clone https://github.com/teeshop/rexgen.git and build it according to
its instructions.

Then add "--enable-rexgen" to ./configure when building john.
