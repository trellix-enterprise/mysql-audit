#ifndef MYSQL_INCL_H
#define MYSQL_INCL_H

#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H
#endif

#define MYSQL_DYNAMIC_PLUGIN 1
#define MYSQL_SERVER 1

//Fix for VIO. We don't want to using method mapping as then a change in the struct will cause the offsets compiled with to 
//be wrong. As is the case with ndb which uses a version of Vio with support for ipv6 similar to 5.5 but different from 5.1
#define DONT_MAP_VIO

#include <my_config.h>
#include <mysql_version.h>
//version 5.5.x doesn't contain mysql_priv.h . We need to add the includes provided by it.


#if MYSQL_VERSION_ID >= 50505
#include <my_pthread.h>
#include <sql_priv.h>
#include <mysql/plugin.h>
#if MYSQL_VERSION_ID >= 50600
//in 5.6 we use the audit plugin interface
#include <mysql/plugin_audit.h>
#endif
#include <sql_parse.h>
#include <sql_class.h>
#include <my_global.h>
#include <sql_connect.h>
#include <sql/sql_base.h>
#include <sql/sql_table.h>
#include <sql/sql_view.h>

//TODO: use mysql mutex instead of pthread
/*
#define pthread_mutex_lock  mysql_mutex_lock
#define pthread_mutex_unlock  mysql_mutex_unlock
#define pthread_mutex_init mysql_mutex_init
#define pthread_mutex_destroy mysql_mutex_destroy
#define pthread_mutex_t mysql_mutex_t
*/

#else
#include <mysql_priv.h>
#endif

#include <violite.h>
#include <events.h>		
#include <my_md5.h>
#include <my_dir.h>
#include <my_sys.h>
#include <my_regex.h>

//5.5 use my_free with a single param. 5.1 use with 2 params
//based on: http://bazaar.launchpad.net/~mysql/myodbc/5.1/view/head:/util/stringutil.h
#ifndef x_free
# if MYSQL_VERSION_ID >= 50500
#  define x_free(A) { void *tmp= (A); if (tmp) my_free((char *) tmp); }
# else
#  define x_free(A) { void *tmp= (A); if (tmp) my_free((char *) tmp,MYF(0)); }
# endif
#endif

//MariaDB doesn't have my_getsystime (returns 100 nano seconds) function. They replaced with my_hrtime_t my_hrtime() which returns microseconds
#if  defined(MARIADB_BASE_VERSION)

#define my_getsystime() ((my_hrtime()).val * 10)
//MariaDB has a kill service that overrides thd_killed as a macro. It also has thd_killed function defined for backwards compatibility, so we redefine it.
#undef thd_killed
extern "C" int thd_killed(const MYSQL_THD thd);
#endif

#endif //MYSQL_INCL_H


