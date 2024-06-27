#ifndef MYSQL_INCL_H
#define MYSQL_INCL_H

#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H
#endif

#define MYSQL_DYNAMIC_PLUGIN 1
#define MYSQL_SERVER 1

// Fix for VIO. We don't want to using method mapping as then a change in
// the struct will cause the offsets compiled with to be wrong.
// As is the case with ndb which uses a version of Vio with support for
// ipv6 similar to 5.5 but different from 5.1
#define DONT_MAP_VIO

#include <my_config.h>
#include <mysql_version.h>

#if MYSQL_VERSION_ID >= 80032
#define TABLE_LIST Table_ref
#endif

// These two are not present in 5.7.9
#if MYSQL_VERSION_ID < 50709
#include <my_pthread.h>
#include <sql_priv.h>
#endif

#include <mysql/plugin.h>

#if MYSQL_VERSION_ID >= 50600
// From 5.6 we use the audit plugin interface
#include <mysql/plugin_audit.h>
#endif

#if defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 100307
// From MariaDB 10.3 we include macro definitions for items like MY_GNUC_PREREQ
#include <my_compiler.h>
#include <my_global.h>
#endif

#include <sql_parse.h>
#include <sql_class.h>

#if !defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 80019
#include <mysql/components/services/mysql_connection_attributes_iterator.h>
#include <mysql/components/my_service.h>
#include <mysql/service_plugin_registry.h>
#endif

#if !defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 80000
using my_bool = bool;
#if MYSQL_VERSION_ID < 80012
#define PLUGIN_VAR_NOSYSVAR 0x0400
#endif
#include <sql/item.h>
#include <sql/log.h>
#include <sql/log_event.h>
#include <sql/mysqld.h>
#include <sql/protocol.h>
#include <sql/sql_lex.h>
#else
#if defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID < 100504
#include <my_global.h>
#endif
typedef struct st_mysql_sys_var SYS_VAR;
#endif

#include <sql_connect.h>
#include <sql/sql_base.h>
#include <sql/sql_table.h>
#include <sql/sql_view.h>
#include <sql/sql_error.h>

// TODO: use mysql mutex instead of pthread
/*
#define pthread_mutex_lock  mysql_mutex_lock
#define pthread_mutex_unlock  mysql_mutex_unlock
#define pthread_mutex_init mysql_mutex_init
#define pthread_mutex_destroy mysql_mutex_destroy
#define pthread_mutex_t mysql_mutex_t
*/

#if MYSQL_VERSION_ID >= 50709
#include <sql/log.h>
#if ! defined(MARIADB_BASE_VERSION)
#include <sql/sql_plugin.h>
#include <sql/auth/auth_common.h>
#endif
#endif

#include <violite.h>
#include <events.h>
#include <my_md5.h>
#include <my_dir.h>
#include <my_sys.h>

// 5.5 use my_free with a single param. 5.1 use with 2 params
// based on: http://bazaar.launchpad.net/~mysql/myodbc/5.1/view/head:/util/stringutil.h
#ifndef x_free
# if MYSQL_VERSION_ID >= 50500
#  define x_free(A) { void *tmp= (A); if (tmp) my_free((char *) tmp); }
# else
#  define x_free(A) { void *tmp= (A); if (tmp) my_free((char *) tmp,MYF(0)); }
# endif
#endif

#if defined(MARIADB_BASE_VERSION)
// MariaDB has a kill service that overrides thd_killed as a macro. It also has thd_killed function defined for backwards compatibility, so we redefine it.
#undef thd_killed
extern "C" int thd_killed(const MYSQL_THD thd);

// MariadDB 10.0.10 removed the include for thd_security_context
#if MYSQL_VERSION_ID >= 100010
extern "C"  char *thd_security_context(MYSQL_THD thd, char *buffer, unsigned int length, unsigned int max_query_len);
#endif
#endif

//Define HAVE_SESS_CONNECT_ATTRS. We define it for mysql 5.6 and above and MariaDB 10.0 and above
#if MYSQL_VERSION_ID >= 50600
#define HAVE_SESS_CONNECT_ATTRS 1
#endif
#include <storage/perfschema/pfs_instr.h>


#if defined(MARIADB_BASE_VERSION) || MYSQL_VERSION_ID < 80000
#include <dlfcn.h>
#endif

namespace compat {
/*************************/
/*     my_getsystime     */
/*************************/
#if  defined(MARIADB_BASE_VERSION)
// MariaDB doesn't have my_getsystime (returns 100 nano seconds) function. They replaced with my_hrtime_t my_hrtime() which returns microseconds
static inline unsigned long long int my_getsystime() { return (my_hrtime()).val * 10; }
#elif MYSQL_VERSION_ID < 80000
static inline unsigned long long int my_getsystime() { return ::my_getsystime(); }
#else
static inline unsigned long long int my_getsystime() {
#ifdef HAVE_CLOCK_GETTIME
  // Performance regression testing showed this to be preferable
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  return (static_cast<unsigned long long int>(tp.tv_sec) * 10000000 +
          static_cast<unsigned long long int>(tp.tv_nsec) / 100);
#else
  return std::chrono::duration_cast<
             std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>>(
             UTC_clock::now().time_since_epoch())
      .count();
#endif /* HAVE_CLOCK_GETTIME */
}
#endif

/*********************************************/
/*   vio_socket_connect                      */
/*********************************************/
#if MYSQL_VERSION_ID >= 50600
#ifndef MYSQL_VIO
#define MYSQL_VIO Vio*
#endif
#if defined(MARIADB_BASE_VERSION) || MYSQL_VERSION_ID < 80000
static inline bool vio_socket_connect(MYSQL_VIO vio, struct sockaddr *addr, socklen_t len, int timeout)
{
    return ::vio_socket_connect(vio, addr, len, timeout);
}
#else
/*********************************************/
/*                                           */
/*  resolve the symbols manually to permit   */
/*  loading of the plugin in their absence   */
/*                                           */
/*********************************************/
extern bool (*_vio_socket_connect)(MYSQL_VIO vio, struct sockaddr *addr, socklen_t len, int timeout);
extern bool (*_vio_socket_connect_80016)(MYSQL_VIO vio, struct sockaddr *addr, socklen_t len, bool nonblocking, int timeout);
extern bool (*_vio_socket_connect_80020)(MYSQL_VIO vio, struct sockaddr *addr, socklen_t len, bool nonblocking, int timeout, bool *connect_done);

static inline bool vio_socket_connect(MYSQL_VIO vio, struct sockaddr *addr, socklen_t len, int timeout)
{
    if (_vio_socket_connect) return _vio_socket_connect(vio, addr, len, timeout);
    if (_vio_socket_connect_80016) return _vio_socket_connect_80016(vio, addr, len, false, timeout);
    if (_vio_socket_connect_80020) return _vio_socket_connect_80020(vio, addr, len, false, timeout, nullptr);
    return true;
}

static inline bool init_vio_socket_connect()
{
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (!handle)
        return false;
    _vio_socket_connect = (decltype(_vio_socket_connect))dlsym(handle, "_Z18vio_socket_connectP3VioP8sockaddrji");
    _vio_socket_connect_80016 = (decltype(_vio_socket_connect_80016))dlsym(handle, "_Z18vio_socket_connectP3VioP8sockaddrjbi");
    _vio_socket_connect_80020 = (decltype(_vio_socket_connect_80020))dlsym(handle, "_Z18vio_socket_connectP3VioP8sockaddrjbiPb");
    dlclose(handle);
    return _vio_socket_connect || _vio_socket_connect_80016 || _vio_socket_connect_80020;
}

extern const std::string & (*_str_session_80026)(int cmd);
extern const LEX_STRING *_command_name;

static inline const char* str_session(int cmd)
{
    if (_str_session_80026) return _str_session_80026(cmd).c_str();
    if (_command_name) return _command_name[cmd].str;
    return "";
}

static inline bool init_str_session()
{
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (!handle)
        return false;
    _command_name = (decltype(_command_name))dlsym(handle, "command_name");
    _str_session_80026 = ((decltype(_str_session_80026))dlsym(handle, "_ZN13Command_names11str_sessionE19enum_server_command") != NULL) 
	? (decltype(_str_session_80026))dlsym(handle, "_ZN13Command_names11str_sessionE19enum_server_command") :
	(decltype(_str_session_80026))dlsym(handle, "_ZN13Command_names11str_sessionB5cxx11E19enum_server_command");
    dlclose(handle);
    return _command_name || _str_session_80026;
}
#endif
#endif

/*********************************************/
/*      PFS_thread::get_current_thread       */
/*********************************************/
#if defined(HAVE_SESS_CONNECT_ATTRS) && defined(MARIADB_BASE_VERSION)
typedef const ::PFS_thread* (*pfs_thread_t)();
extern pfs_thread_t _pfs_thread_get_current_thread;
extern PSI_v1* _psi_interface;
namespace PFS_thread  {
static inline const ::PFS_thread* get_current_thread()
{
    // Try PFS_thread and PSI_hook when MariaDB
    if (_pfs_thread_get_current_thread) return _pfs_thread_get_current_thread();
    if (_psi_interface) return (::PFS_thread*)_psi_interface->get_thread();
    return NULL;
}
}
static inline bool init_PFS_thread_get_current_thread()
{
    // obtain the PFS_thread::get_current_thread() address if it is exported
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (handle) {
        _pfs_thread_get_current_thread = (pfs_thread_t)dlsym(handle, "_ZN10PFS_thread18get_current_threadEv");
        dlclose(handle);
    }
    // obtain the PSI interface address
    if (PSI_hook)
        _psi_interface = (PSI_v1*)PSI_hook->get_interface(PSI_VERSION_1);
    if (!_pfs_thread_get_current_thread && !_psi_interface)
        sql_print_information("Failed to initialize Performance Schema. 'osuser' and 'appname' will not be avalilable.");
    return true;
}
#elif defined(HAVE_SESS_CONNECT_ATTRS)
namespace PFS_thread  {
static inline const ::PFS_thread* get_current_thread()
{
    // Use PFS_thread when MySQL
    return ::PFS_thread::get_current_thread();
}
}
#endif
static inline bool init()
{
#if !defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 80000
    return init_vio_socket_connect() && init_str_session();
#elif defined(HAVE_SESS_CONNECT_ATTRS) && defined(MARIADB_BASE_VERSION)
    return init_PFS_thread_get_current_thread();
#else
    return true;
#endif
}
}

#endif // MYSQL_INCL_H
