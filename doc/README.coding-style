This coding style is based on Kernel CodingStyle
(https://www.kernel.org/doc/Documentation/process/coding-style.rst).

Chapter 1: Indentation

1.1 Indentation is one tab per level. Recommended tab width is 4 or 8 but it
    mostly just affects where a line exceeds max length.

1.2 Indent with tabs, align with spaces. E.g.

'->' is tab, '.' is space.

void *memmem(const void *haystack, size_t haystack_len,
.............const void *needle, size_t needle_len)
{
->	haystack_ = (char *)haystack;
->	needle_ = (char *)needle;
->	last = haystack_+(haystack_len - needle_len + 1);
->	for (; haystack_ < last; ++haystack_)
->	{
->	->	if (hash == hay_hash &&
->	->	....*haystack_ == *needle_ &&
->	->	....!memcmp (haystack_, needle_, needle_len))
->	->	->	return haystack_;

->	->	hay_hash += *(haystack_+needle_len);
->	}

->	return NULL;
}

1.3 Ease multiple indentation levels in switch(), for(), while()...

	switch (suffix) {
	case 'G':
	case 'g':
		mem <<= 30;
		break;
	case 'M':
	case 'm':
		mem <<= 20;
		break;
	case 'K':
	case 'k':
		mem <<= 10;
		/* fall through */
	default:
		break;
	}

	for (size = 0; size < PASSWORD_HASH_SIZES; size++)
	if (format->methods.binary_hash[size] &&
	    format->methods.get_hash[size](i) !=
	    format->methods.binary_hash[size](binary)) {
		do_something();
	}

1.4 Don't put multiple statements on a single line. A good example is:

	if (condition)
		do_something();


Chapter 2: Breaking long lines and strings

The recommended limit on the length of lines is 120 columns when viewed with a
tab width of 4, or 132 columns viewed with a tab width of 8, or something along
those lines.

However, there are some cases where lines can exceed 120 columns:  Avoid
breaking user-visible strings such as print messages, because that breaks the
ability to grep for them.


Chapter 3: Placing Braces and Spaces

3.1 Braces

3.1.1 Function

Put the opening brace at the beginning of the next line, thus:

int function(int x)
{
	body of function
}

3.1.2 Others

Put the opening brace last on the next line, thus:

	if (x is true) {
		we do y
	}

This applies to all non-function statement blocks (if, switch, for,
while, do).  E.g.:

	switch (action) {
	case KOBJ_ADD:
		return "add";
	case KOBJ_REMOVE:
		return "remove";
	case KOBJ_CHANGE:
		return "change";
	default:
		return NULL;
	}

Note that the closing brace is empty on a line of its own, _except_ in
the cases where it is followed by a continuation of the same statement,
ie a "while" in a do-statement or an "else" in an if-statement, like
this:

	do {
		body of do-loop
	} while (condition);

and

	if (x == y) {
		..
	} else if (x > y) {
		...
	} else {
		....
	}

3.2 Spaces

3.2.1 Use a space after (most) keywords.

Use a space after these keywords:

	if, switch, case, for, do, while

but not with sizeof, typeof, alignof, or __attribute__.  E.g.,

	s = sizeof(struct file);

3.2.2 Do not add spaces around (inside) parenthesized expressions.

This example is *bad*:

	s = sizeof( struct file );

3.2.3 When declaring pointer, the preferred use of '*' is adjacent to the data
      name or function name. E.g.:

	char *linux_banner;
	unsigned long long memparse(char *ptr, char **retptr);
	char *match_strdup(substring_t *s);

3.2.4 When type casting, we recommend a space before '*' but not after the
      right paren.  E.g:

	byte_len = strlen((char *)utf8_string);

3.2.5 Use one space around (on each side of) most binary and ternary operators,
      such as any of these:

	=  +  -  <  >  *  /  %  |  &  ^  <=  >=  ==  !=  ?  :

but no space after unary operators:

	&  *  +  -  ~  !  sizeof  typeof  alignof  __attribute__  defined

no space before the postfix increment & decrement unary operators:

	++  --

no space after the prefix increment & decrement unary operators:

	++  --

and no space around the '.' and "->" structure member operators.

3.2.6 Don't leave whitespace at the end of lines, or of files.  The last line
      of a file should have a linefeed, but no blank lines.

3.2.7 There should not be any indentation before labels.  E.g:

void f()
{
	...
out:
	free(p);
	return;
}


Chapter 4: Naming

Global variables (to be used only if you _really_ need them) need to
have descriptive names, as do global functions.  If you have a function
that counts the number of active users, you should call that
"count_active_users()" or similar, you should _not_ call it "cntusr()".

We use names prefixed by crk_ for global functions in cracker.c, ldr_ for
ones from loader.c and so on.


Chapter 5: Declaration

5.1 Functions declaration

In function prototypes, include parameter names with their data types.
Although this is not required by the C language, it is preferred in Linux
because it is a simple way to add valuable information for the reader.

5.2 Variables declaration

Until 2020 or so, we wanted everything declared at block start and with a blank
line after variables declaration. E.g:

void function(void)
{
	unsigned char master[32];

	sevenzip_kdf((unsigned char *)saved_key[index], master);
}

We have since relaxed that, so variable declarations can occur right before the
use of it, especially if it gains readability or preprocessing logics.

We still do not want C99 style declaration within e.g. a for statement as in:

	for (int i = 0; ... )


Chapter 6: Commenting

6.1 C89 style and C99 comment style

C89:

/* ... */

C99:

// ...

We recommend using the C89 style for most everything, but C99 style may be used
e.g. for quickly commenting out a line of code that we don't want permanently
removed.
