#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(mysql-audit-plugin, [dev])
AC_CONFIG_AUX_DIR([config-aux])
AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([src/audit_plugin.cc])
AC_CONFIG_HEADER([include/_config.h])

AC_DEFUN([CHECK_DEBUG], [
        debug_default="no"
        AC_ARG_ENABLE(debug, [  --enable-debug=[no/yes] turn on debugging
                       [default=$debug_default]],, enable_debug=$debug_default)
        AC_MSG_CHECKING(whether to enable debugging)

        if test "x$enable_debug" = "xyes"; then
        CPPFLAGS="$CPPFLAGS -g -D_DEBUG"
                AC_MSG_RESULT(yes)
        else
        		CPPFLAGS="$CPPFLAGS -g -O2 -DDBUG_OFF"
                AC_MSG_RESULT(no)
		fi

])

dnl Run tests using C++ compiler 
dnl AC_LANG(C++)

# initialize automake
AM_INIT_AUTOMAKE([1.8 foreign tar-ustar])


#check debug
CHECK_DEBUG

#check for mysql src 
sinclude(config/ac_mysql.m4)
MYSQL_SRC_TEST
MYSQL_PLUGIN_DIR_TEST
MYSQL_LIB_SERVICES_TEST
AC_SUBST(MYSQL_INC)
AC_SUBST(MYSQL_PLUGIN_DIR)
AC_SUBST(MYSQL_LIBSERVICES)
#yajl include dir
YAJL_INC=-I`cd yajl/include && pwd`
AC_SUBST(YAJL_INC)
#udis86 include
UDIS_INC=-I`cd udis86 && pwd`
AC_SUBST(UDIS_INC)

#pcre
(cd pcre && CFLAGS=-fPIC ./configure --enable-utf --disable-cpp --disable-shared --enable-static )
if test $? -ne 0 ; then 
	AC_MSG_ERROR([Failed pcre configure])
fi


dnl AC_PROG_CC set CFLAGS=-g if CFLAGS was empty before. Reset to empty value
dnl when not building a debug version.
dnl if test "$ac_test_CFLAGS" != set -a "$enable_debug" = no; then
dnl  CFLAGS=
dnl fi
dnl AC_PROG_CXX set CXXFLAGS=-g if CXXFLAGS was empty before. Reset to empty
dnl value when not building a debug version.
dnl if test "$ac_test_CXXFLAGS" != set -a "$enable_debug" = no; then
dnl   CXXFLAGS=
dnl fi


#check for programs
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_CPP

AC_PATH_PROG(MV, mv, mv)
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(SED, sed, sed)
AC_PATH_PROG(CMP, cmp, cmp)
AC_PATH_PROG(CHMOD, chmod, chmod)
AC_PATH_PROG(HOSTNAME, hostname, hostname)
AC_PATH_PROG(DIFF, diff, diff)


#for some reason we need to add -D_GNU_SOURCE
#this should have been added by AC_GNU_SOURCE but doesn't seem
#to work
#CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS"

#add the mysql flags needed (not needed as we put this in mysql_inc.h)
#CPPFLAGS="$CPPFLAGS -DMYSQL_DYNAMIC_PLUGIN -DMYSQL_SERVER"

#we can add the following flags for better error catching: -Werror -Wimplicit
CPPFLAGS="$CPPFLAGS -Werror -Wall"
CFLAGS="$CFLAGS -Wimplicit"
# From MySQL: Disable exceptions as they seams to create problems with gcc and threads.
CXXFLAGS="-fno-implicit-templates -fno-exceptions -fno-rtti -Wno-reorder -Wno-strict-aliasing"

#add pthread libs
LIBS="$LIBS -lpthread"




#make sure we have const
AC_C_CONST
AC_TYPE_SIZE_T

#version stuff
if test -z "$MYSQL_AUDIT_PLUGIN_VERSION" ;then
	MYSQL_AUDIT_PLUGIN_VERSION=1.0.0
fi
if test -z "$MYSQL_AUDIT_PLUGIN_REVISION" ;then
	MYSQL_AUDIT_PLUGIN_REVISION=99999
fi
if test -z "$MYSQL_AUDIT_PLUGIN_SYMBOL_VERSION" ;then
        MYSQL_AUDIT_PLUGIN_SYMBOL_VERSION=${MYSQL_AUDIT_PLUGIN_VERSION//./_}_$MYSQL_AUDIT_PLUGIN_REVISION
fi


AC_SUBST(MYSQL_AUDIT_PLUGIN_VERSION)
AC_SUBST(MYSQL_AUDIT_PLUGIN_REVISION)
echo "Version: $MYSQL_AUDIT_PLUGIN_VERSION-$MYSQL_AUDIT_PLUGIN_REVISION Symbol version: $MYSQL_AUDIT_PLUGIN_SYMBOL_VERSION"
CPPFLAGS="$CPPFLAGS -DMYSQL_AUDIT_PLUGIN_VERSION='\"$MYSQL_AUDIT_PLUGIN_VERSION\"'"
CPPFLAGS="$CPPFLAGS -DMYSQL_AUDIT_PLUGIN_REVISION='\"$MYSQL_AUDIT_PLUGIN_REVISION\"'"
CPPFLAGS="$CPPFLAGS '-DMYSQL_AUDIT_PLUGIN_SYMBOL_VERSION()=extern const char audit_plugin_version_$MYSQL_AUDIT_PLUGIN_SYMBOL_VERSION'"

# Percona`s MySQL macro
if [[ "$PERCONA_BUILD" = "true" ]]; then
	CPPFLAGS="$CPPFLAGS -DPERCONA_BUILD" # Percona`s build macro, used to distinguish between MySQL/MariaDB build VS Percona build
fi

#subst the relevant variables
AC_SUBST(CPPFLAGS)
AC_SUBST(CXXLAGS)
AC_SUBST(CLAGS)


AC_CONFIG_FILES([Makefile
		src/Makefile
		yajl/Makefile
		yajl/src/Makefile
		udis86/Makefile
		udis86/libudis86/Makefile
				])
AC_OUTPUT


AC_MSG_NOTICE([CPPFLAGS: $CPPFLAGS])

 
