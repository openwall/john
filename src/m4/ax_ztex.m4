#
# AX_ZTEX
#
# If configured to support ZTEX USB-FPGA module with --enable-ztex=yes:
# - check for headers and libraries
# - add Makefiles
# - set ZTEX_SUBDIRS, ZTEX_LIBS
#
AC_DEFUN_ONCE([AX_ZTEX], [

AC_ARG_ENABLE([ztex],
	[AC_HELP_STRING([--enable-ztex],[Support ZTEX USB-FPGA module 1.15y])],
	[ztex=$enableval], [ztex=no])

ZTEX_SUBDIRS=""
ZTEX_LIBS=""

if test "x$ztex" = xyes; then

AC_CHECK_HEADER([libusb-1.0/libusb.h],
	[AC_CHECK_LIB([usb-1.0], [libusb_init],
		[],
		[AC_MSG_FAILURE(ZTEX USB-FPGA module requires libusb-1.0.)]
	)],
	[AC_MSG_FAILURE(ZTEX USB-FPGA module requires libusb-1.0.)]
)

AC_CONFIG_FILES([ztex/Makefile ztex/pkt_comm/Makefile])

ZTEX_SUBDIRS="ztex"
ZTEX_LIBS="ztex/*.o ztex/pkt_comm/*.o -lusb-1.0"

fi

AC_SUBST([ZTEX_SUBDIRS])
AC_SUBST([ZTEX_LIBS])
])dnl
