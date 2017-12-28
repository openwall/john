dnl ======================================================================
dnl changes to default _AC_INIT_HELP macro Copyright 2014, JimF
dnl
dnl This is JTR specific version of the --help screen.  We will put here
dnl EXACTLY what we want shown for ./configure --help in JtR.
dnl The only thing different than the macro in my general.m4 is I edited
dnl the directory stuff out.
dnl
dnl The 'original' macro was found (on my cygwin install) at
dnl /usr/share/autoconf/autoconf/general.m4
dnl I have kept the original format, I simply remove some directory 'help'
dnl we did not want.
dnl
dnl ======================================================================
dnl _AC_INIT_HELP
dnl -------------
dnl Handle the `configure --help' message.
m4_define([_AC_INIT_HELP],
[m4_divert_push([HELP_BEGIN])dnl

dnl
dnl Report the --help message.
dnl
if test "$ac_init_help" = "long"; then
  dnl Omit some internal or obsolete options to make the list less imposing.
  dnl This message is too long to be a string in the A/UX 3.1 sh.
  cat <<_ACEOF
\`configure' configures m4_ifset([AC_PACKAGE_STRING],
			[AC_PACKAGE_STRING],
			[this package]) to adapt to many kinds of systems.

Usage: $[0] [[OPTION]]... [[VAR=VALUE]]...

[To assign environment variables (e.g., CC, CFLAGS...), specify them as
VAR=VALUE.  See below for descriptions of some of the useful variables.

Defaults for the options are specified in brackets.

Configuration:
  -h, --help              display this help and exit
      --help=short        display options specific to this package
      --help=recursive    display the short help of all the included packages
  -V, --version           display version information and exit
  -q, --quiet, --silent   do not print \`checking ...' messages
      --cache-file=FILE   cache test results in FILE [disabled]
  -C, --config-cache      alias for \`--cache-file=config.cache'
  -n, --no-create         do not create output files
      --srcdir=DIR        find the sources in DIR [configure dir or \`..']

Installation directories:
][
By default, \`make install' will install all the files in \`$ac_default_prefix'
You can specify location other than \`$ac_default_prefix' using \`--prefix',
for instance \`--prefix=\$HOME/bin'.

Development/QA options

Some --enable-xxx options are listed with a \`*' preceding their description. These
are developer/QA testing options, and should not be enabled unless you know what
you are doing with them. These will significantly degrade the runtime performance
and or memory usage of JtR. and are not designed for a normal user build]
m4_divert_pop([HELP_BEGIN])dnl
dnl The order of the diversions here is
dnl - HELP_BEGIN
dnl   which may be extended by extra generic options such as with X or
dnl   AC_ARG_PROGRAM.  Displayed only in long --help.
dnl
dnl - HELP_CANON
dnl   Support for cross compilation (--build, --host and --target).
dnl   Display only in long --help.
dnl
dnl - HELP_ENABLE
dnl   which starts with the trailer of the HELP_BEGIN, HELP_CANON section,
dnl   then implements the header of the non generic options.
dnl
dnl - HELP_WITH
dnl
dnl - HELP_VAR
dnl
dnl - HELP_VAR_END
dnl
dnl - HELP_END
dnl   initialized below, in which we dump the trailer (handling of the
dnl   recursion for instance).
m4_divert_push([HELP_ENABLE])dnl
_ACEOF
fi

if test -n "$ac_init_help"; then
m4_ifset([AC_PACKAGE_STRING],
[  case $ac_init_help in
     short | recursive ) echo "Configuration of AC_PACKAGE_STRING:";;
   esac])
  cat <<\_ACEOF
m4_divert_pop([HELP_ENABLE])dnl
m4_divert_push([HELP_END])dnl

Report bugs to m4_ifset([AC_PACKAGE_BUGREPORT], [<AC_PACKAGE_BUGREPORT>],
  [the package provider]).dnl
m4_ifdef([AC_PACKAGE_NAME], [m4_ifset([AC_PACKAGE_URL], [
AC_PACKAGE_NAME home page: <AC_PACKAGE_URL>.])dnl
m4_if(m4_index(m4_defn([AC_PACKAGE_NAME]), [GNU ]), [0], [
General help using GNU software: <http://www.gnu.org/gethelp/>.])])
_ACEOF
ac_status=$?
fi

if test "$ac_init_help" = "recursive"; then
  dnl If there are subdirs, report their specific --help.
  for ac_dir in : $ac_subdirs_all; do test "x$ac_dir" = x: && continue
    test -d "$ac_dir" ||
      { cd "$srcdir" && ac_pwd=`pwd` && srcdir=. && test -d "$ac_dir"; } ||
      continue
    _AC_SRCDIRS(["$ac_dir"])
    cd "$ac_dir" || { ac_status=$?; continue; }
    dnl Check for guested configure.
    if test -f "$ac_srcdir/configure.gnu"; then
      echo &&
      $SHELL "$ac_srcdir/configure.gnu" --help=recursive
    elif test -f "$ac_srcdir/configure"; then
      echo &&
      $SHELL "$ac_srcdir/configure" --help=recursive
    else
      AC_MSG_WARN([no configuration information is in $ac_dir])
    fi || ac_status=$?
    cd "$ac_pwd" || { ac_status=$?; break; }
  done
fi

test -n "$ac_init_help" && exit $ac_status
m4_divert_pop([HELP_END])dnl
])dnl _AC_INIT_HELP
