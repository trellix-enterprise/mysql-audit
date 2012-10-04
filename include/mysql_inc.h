#ifndef MYSQL_INCL_H
#define MYSQL_INCL_H

#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H
#endif

#define MYSQL_DYNAMIC_PLUGIN
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



#endif //MYSQL_INCL_H


