dnl ---------------------------------------------------------------------------
dnl Macro: MYSQL_SRC_TEST
dnl ---------------------------------------------------------------------------

dir_resolve() dnl {{{
{
  pwd=`pwd`
  cd "$1" 2>/dev/null || cd "${pwd}/${1}" 2>/dev/null
  if test "$?" = "0"; then
    echo `pwd -P`
  else
    echo "$1"
  fi
}
dnl }}} 

AC_DEFUN([MYSQL_SRC_TEST], [
  AC_MSG_CHECKING(for mysql source code)
  AC_ARG_WITH(mysql,
  [AS_HELP_STRING([--with-mysql=PATH], [MySQL src directory required to build.])],
  [
    withval=`dir_resolve "$withval"`
	ac_mysql_source_dir="$withval"
    HEADERS="include/my_dir.h include/mysql/plugin.h include/mysql.h include/mysql_version.h include/config.h include/my_config.h"
    for file in $HEADERS; do
      if ! test -r "$withval/$file"; then
         AC_MSG_ERROR([Failed to find required header file $file in $withval, check the path and make sure you've run './configure ..<options>.. && cd include && make' in MySQL 5.1 sources dir or 'cmake . && make' in MySQL 5.5 sources dir.])
      fi
    done 
    AC_DEFINE([MYSQL_SRC], [1], [Source directory for MySQL])
    MYSQL_INC="-I$withval/sql -I$withval/include -I$withval/regex -I$withval"
    AC_MSG_RESULT(["$withval"])
  ],
  [
    AC_MSG_ERROR(["No mysql source provided. Please specify --with-mysql=<mysql source dir>!"])
  ])
])

dnl ---------------------------------------------------------------------------
dnl Macro: MYSQL_PLUGIN_DIR_TEST
dnl ---------------------------------------------------------------------------

AC_DEFUN([MYSQL_PLUGIN_DIR_TEST], [
  AC_MSG_CHECKING([for mysql plugin dir])
  ac_mysql_plugin_dir=
  AC_ARG_WITH([mysql-plugindir],
	[AS_HELP_STRING([--with-mysql-plugindir=PATH], [MySQL plugin directory where audit plugin is to be copied to])],
	[
	  ac_mysql_plugin_dir=`dir_resolve "$withval"`
	  if test -d "$ac_mysql_plugin_dir/" ; then
		MYSQL_PLUGIN_DIR="$ac_mysql_plugin_dir"			
		AC_MSG_RESULT([yes: Using $ac_mysql_plugin_dir])
	  else
		AC_MSG_ERROR([invalid MySQL plugin directory : $ac_mysql_plugin_dir])
	  fi
	],
	[
	  ac_mysql_plugin_dir=/usr/lib/mysql/plugin
	  MYSQL_PLUGIN_DIR="$ac_mysql_plugin_dir"		  
	  AC_MSG_RESULT([--with-mysql-plugindir was not set. Using $ac_mysql_plugin_dir])
	]
  )
])


dnl ---------------------------------------------------------------------------
dnl Macro: MYSQL_LIB_SERVICES : 5.5 services lib to add to linker
dnl ---------------------------------------------------------------------------

AC_DEFUN([MYSQL_LIB_SERVICES_TEST], [
  AC_MSG_CHECKING([for mysql libmysqlservices])
  ac_mysql_libservices=
  AC_ARG_WITH([mysql-libservices],
	[AS_HELP_STRING([--with-mysql-libservices=PATH], [MySQL libmysqlservices.a location (relevant for 5.5 only)])],
	[	  	  
	  t_lib_dir=`dirname "$withval"`
	  t_lib_dir=`dir_resolve "$t_lib_dir"`
	  t_lib_file=`basename "$withval"`
	  ac_mysql_libservices="$t_lib_dir/$t_lib_file"
	  if test -f "$ac_mysql_libservices" ; then
		MYSQL_LIBSERVICES="$ac_mysql_libservices"			
		AC_MSG_RESULT([yes: Using $ac_mysql_libservices])
	  else
		AC_MSG_ERROR([invalid MySQL libmysqlservices : $ac_mysql_libservices])
	  fi
	],
	[
	  if test -f "$ac_mysql_source_dir/VERSION"; then 
          source "$ac_mysql_source_dir/VERSION"
          if test "$MYSQL_VERSION_MAJOR.$MYSQL_VERSION_MINOR" = "5.5"; then
			AC_MSG_ERROR([no mysql-libservices. Required for MySQL 5.5])
		  fi	  
	  fi
	  ac_mysql_libservices=""
	  MYSQL_LIBSERVICES="$ac_mysql_libservices"		  
	  AC_MSG_RESULT([--with-mysql-libservices was not set.])
	]
  )
])
