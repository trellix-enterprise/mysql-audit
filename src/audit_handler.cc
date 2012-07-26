/*
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

/*
 * audit_handler.cc
 *
 *  Created on: Feb 6, 2011
 *      Author: guyl
 */
#include "audit_handler.h"
//for definition of sockaddr_un
#include <sys/un.h>
#include "static_assert.h"
  
  
  
/**
 * Will write into buff the date prefix for txt formatter. Return the number of bytes written
 * (not including null terminate).
 */
static int log_date_prefix(char * buff, size_t buff_size)
{
  struct tm tm_tmp;
  time_t result= time(NULL);
  localtime_r(&result, &tm_tmp);
  //my_snprintf is limited regarding formatting but sufficient for this
  return my_snprintf(buff, buff_size, "%02d%02d%02d %2d:%02d:%02d: ",
		     tm_tmp.tm_year % 100,
		     tm_tmp.tm_mon+1,
		     tm_tmp.tm_mday,
		     tm_tmp.tm_hour,
		     tm_tmp.tm_min,
		     tm_tmp.tm_sec);
}
	    
	    
//utility macro to log also with a date as a prefix
#define log_with_date(f, ...) do{		\
    struct tm tm_tmp;				\
    time_t result= time(NULL);			\
    localtime_r(&result, &tm_tmp);		\
    fprintf(f, "%02d%02d%02d %2d:%02d:%02d: ",	\
	    tm_tmp.tm_year % 100,		\
	    tm_tmp.tm_mon+1,			\
	    tm_tmp.tm_mday,			\
	    tm_tmp.tm_hour,			\
	    tm_tmp.tm_min,			\
	    tm_tmp.tm_sec);			\
    fprintf(f, __VA_ARGS__);			\
  }while(0)
		       
		       
//initialize static stuff
ThdOffsets Audit_formatter::thd_offsets = { 0 };
Audit_handler * Audit_handler::m_audit_handler_list[Audit_handler::MAX_AUDIT_HANDLERS_NUM];
const char * Audit_json_formatter::DEF_MSG_DELIMITER = "\\n";
		       
#define C_STRING_WITH_LEN(X) ((char *) (X)), ((size_t) (sizeof(X) - 1))
		       
		       
const char *  Audit_formatter::retrive_object_type (TABLE_LIST *pObj)
{
  if (pObj->view)
    {
      return "VIEW";
    }	
  return "TABLE";
}
			     
			     
void Audit_handler::stop_all()
{
  for (int i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
    {
      if (m_audit_handler_list[i] != NULL)
	{
	  m_audit_handler_list[i]->set_enable(false);
	}
    }
}
				 
void Audit_handler::log_audit_all(ThdSesData *pThdData)
{
  for (int i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
    {
      if (m_audit_handler_list[i] != NULL)
	{
	  m_audit_handler_list[i]->log_audit(pThdData);
	}
    }
}
				     
void Audit_handler::set_enable(bool val)
{
  lock_exclusive();
  if (m_enabled == val) //we are already enabled simply return
    {
      unlock();
      return;
    }
  m_enabled = val;
  if (m_enabled)
    {
      //call the startup of the handler
      handler_start();
    }
  else
    {
      //call the cleanup of the handler
      handler_stop();
    }
  unlock();
}
						 
void Audit_handler::log_audit(ThdSesData *pThdData)
{
  lock_shared();
  if (!m_enabled)
    {
      unlock();
      return;
    }
  //sanity check that offsets match
  //we can also consider using secutiry context function to do some sanity checks
  //  char buffer[2048];
  //  thd_security_context(thd, buffer, 2048, 2000);
  //  fprintf(log_file, "info from security context: %s\n", buffer);
  unsigned long inst_thread_id = Audit_formatter::thd_inst_thread_id(pThdData->getTHD());
  unsigned long plug_thread_id = thd_get_thread_id(pThdData->getTHD());
  if (inst_thread_id != plug_thread_id)
    {
      if (m_print_offset_err)
	{
	  m_print_offset_err = false;
	  sql_print_error(
			  "%s Thread id from thd_get_thread_id doesn't match calculated value from offset %lu <> %lu. Aborting!",
			  AUDIT_LOG_PREFIX, inst_thread_id, plug_thread_id);
        }		
    }
  else
    {//offsets are good
      m_print_offset_err = true; //mark to print offset err to log incase we encounter in the future
      handler_log_audit(pThdData);
    }
  unlock();
}

ssize_t Audit_file_handler::write(const char * data, size_t size)
{
  return my_fwrite(m_log_file, (uchar *) data, size, MYF(0));
}

void Audit_file_handler::handler_start()
{
  pthread_mutex_lock(&LOCK_io);
  char format_name[FN_REFLEN];
  fn_format(format_name, m_filename, "", "", MY_UNPACK_FILENAME);
  m_log_file = my_fopen(format_name, O_RDWR | O_APPEND, MYF(0));
  if (!m_log_file)
    {
      sql_print_error(
		      "%s unable to create %s: %s. audit file handler disabled!!",
		      AUDIT_LOG_PREFIX, m_filename, strerror(errno));
      m_enabled = false;
    }
  else
    {
      ssize_t res = m_formatter->start_msg_format(this);
      /*
	sanity check of writing to the log. If we fail. We will print an erorr and disable this handler.
      */
      if (res < 0 || fflush(m_log_file) != 0)
        {
	  sql_print_error(
			  "%s unable to write to %s: %s. Disabling audit handler.",
			  AUDIT_LOG_PREFIX, m_log_file, strerror(errno));
	  close_file();
	  m_enabled = false;
        }
    }
  pthread_mutex_unlock(&LOCK_io);
}
void Audit_file_handler::handler_stop()
{
  pthread_mutex_lock(&LOCK_io);
  m_formatter->stop_msg_format(this);
  close_file();
  pthread_mutex_unlock(&LOCK_io);
}

void Audit_file_handler::handler_log_audit(ThdSesData *pThdData)
{
  pthread_mutex_lock(&LOCK_io);
  m_formatter->event_format(pThdData, this);
  if (++m_sync_counter >= m_sync_period && m_sync_period)
    {
      m_sync_counter = 0;
      //Note fflush() only flushes the user space buffers provided by the C library.
      //To ensure that the data is physically stored on disk the kernel buffers must be flushed too,
      //e.g. with sync(2) or fsync(2).
      fflush(m_log_file);
      int fd = fileno(m_log_file);
      my_sync(fd, MYF(MY_WME));
    }
  pthread_mutex_unlock(&LOCK_io);
}

/////////////////// Audit_socket_handler //////////////////////////////////

ssize_t Audit_socket_handler::write(const char * data, size_t size)
{
  return vio_write(m_vio, (const uchar *) data, size);
}

void Audit_socket_handler::handler_start()
{
  pthread_mutex_lock(&LOCK_io);
  //open the socket
  int sock = socket(AF_UNIX,SOCK_STREAM,0);
  if (sock < 0)
    {
      sql_print_error(
		      "%s unable to create socket: %s. audit socket handler disabled!!",
		      AUDIT_LOG_PREFIX, strerror(errno));
      m_enabled = false;
      pthread_mutex_unlock(&LOCK_io);
      return;
    }

  //connect the socket
  m_vio= vio_new(sock, VIO_TYPE_SOCKET, VIO_LOCALHOST);
  struct sockaddr_un UNIXaddr;
  UNIXaddr.sun_family = AF_UNIX;
  strmake(UNIXaddr.sun_path, m_sockname, sizeof(UNIXaddr.sun_path)-1);
  if (my_connect(sock,(struct sockaddr *) &UNIXaddr, sizeof(UNIXaddr),
		 m_connect_timeout))
    {
      sql_print_error(
		      "%s unable to connect to socket: %s. err: %s. audit socket handler disabled!!",
		      AUDIT_LOG_PREFIX, m_sockname, strerror(errno));
      close_vio();
      m_enabled = false;
      pthread_mutex_unlock(&LOCK_io);
      return;

    }
  ssize_t res = m_formatter->start_msg_format(this);
  /*
    sanity check of writing to the log. If we fail. We will print an erorr and disable this handler.
  */
  if (res < 0)
    {
      sql_print_error(
		      "%s unable to write to %s: %s. Disabling audit handler.",
		      AUDIT_LOG_PREFIX, m_sockname, strerror(errno));
      close_vio();
      m_enabled = false;
    }
  pthread_mutex_unlock(&LOCK_io);
}
void Audit_socket_handler::handler_stop()
{
  pthread_mutex_lock(&LOCK_io);
  m_formatter->stop_msg_format(this);
  close_vio();
  pthread_mutex_unlock(&LOCK_io);
}

void Audit_socket_handler::handler_log_audit(ThdSesData *pThdData)
{
  pthread_mutex_lock(&LOCK_io);
  m_formatter->event_format(pThdData, this);
  pthread_mutex_unlock(&LOCK_io);
}

//////////////////////// Audit Socket handler end ///////////////////////////////////////////




static inline yajl_gen_status yajl_add_string(yajl_gen hand, const char * str)
{
  return yajl_gen_string(hand, (const unsigned char*)str, strlen(str));
}

static inline void yajl_add_string_val(yajl_gen hand, const char * name, const char* val)
{
  if(0 == val)
    {
      return; //we don't add NULL values to json
    }
  yajl_add_string(hand, name);
  yajl_add_string(hand, val);
}

static inline void yajl_add_string_val(yajl_gen hand, const char * name, const char* val, size_t val_len)
{
  yajl_add_string(hand, name);
  yajl_gen_string(hand, (const unsigned char*)val, val_len);
}

static inline void yajl_add_uint64(yajl_gen gen, const char * name, uint64 num)
{
  const size_t max_int64_str_len = 21;
  char buf[max_int64_str_len];
  snprintf(buf, max_int64_str_len, "%llu", num);
  yajl_add_string_val(gen, name, buf);
}
static inline void yajl_add_obj( yajl_gen gen,  const char *db,const char* ptype,const char * name =NULL)
{
  yajl_add_string_val(gen, "db", db);
  if (name)
    {
      yajl_add_string_val(gen, "name", name);
    }
  yajl_add_string_val(gen, "obj_type",ptype);
}

//void Audit_file_handler::print_sleep (THD *thd, int delay_ms)
//{
//
//    unsigned long thdid = thd_get_thread_id(thd);
//    yajl_gen gen = yajl_gen_alloc(&config, NULL);
//    yajl_gen_array_open(gen);
//    yajl_gen_map_open(gen);
//    yajl_add_string_val(gen, "msg-type", "activity");
//    uint64 ts = my_getsystime() / (10000);
//    yajl_add_uint64(gen, "date", ts);
//    yajl_add_uint64(gen, "thread-id", thdid);
//    yajl_add_uint64(gen, "audit is going to sleep for ", delay_ms);
//    yajl_gen_map_close(gen);
//    yajl_gen_array_close(gen);
//    fflush(m_log_file);
//    int fd = fileno(m_log_file);
//    my_sync(fd, MYF(MY_WME));
//
//}
ssize_t Audit_json_formatter::event_format(ThdSesData* pThdData, IWriter * writer)
{
  unsigned long thdid = thd_get_thread_id(pThdData->getTHD());
  query_id_t qid = thd_inst_query_id(pThdData->getTHD());
  int command = thd_inst_command(pThdData->getTHD());

	
  Security_context * sctx = thd_inst_main_security_ctx(pThdData->getTHD());

  //initialize yajl
  yajl_gen gen = yajl_gen_alloc(&config, NULL);
  yajl_gen_map_open(gen);
  yajl_add_string_val(gen, "msg-type", "activity");
  //TODO: get the start date from THD (but it is not in millis. Need to think about how we handle this)
  //for now simply use the current time.
  //my_getsystime() time since epoc in 100 nanosec units. Need to devide by 1000*(1000/100) to reach millis
  uint64 ts = my_getsystime() / (10000);
  yajl_add_uint64(gen, "date", ts);
  yajl_add_uint64(gen, "thread-id", thdid);
  yajl_add_uint64(gen, "query-id", qid);
  yajl_add_string_val(gen, "user", sctx->user);
  yajl_add_string_val(gen, "priv_user", sctx->priv_user);
  yajl_add_string_val(gen, "host", sctx->host);
  yajl_add_string_val(gen, "ip", sctx->ip);    
  const char *cmd = pThdData->getCmdName();
  //only print tables if  lex is not null and it is not a quit command
  LEX * pLex = Audit_formatter::thd_lex(pThdData->getTHD());
  QueryTableInf *pQuery_cache_table_list =  getQueryCacheTableList1 (pThdData->getTHD());
  if (pLex && command != COM_QUIT && pLex->query_tables == NULL && pQuery_cache_table_list)
    {
      yajl_add_string_val(gen, "cmd", "select");
      yajl_add_string(gen, "objects");
      yajl_gen_array_open(gen);
      for (int i=0;i<pQuery_cache_table_list->num_of_elem && i < MAX_NUM_QUERY_TABLE_ELEM && pQuery_cache_table_list->num_of_elem >=0;i++)
        {
	  yajl_gen_map_open(gen);
	  yajl_add_obj (gen, pQuery_cache_table_list->db[i],pQuery_cache_table_list->object_type[i],pQuery_cache_table_list->table_name[i] );
	  yajl_gen_map_close(gen);

        }
      yajl_gen_array_close(gen);

    }
  else 
    {
      yajl_add_string_val(gen, "cmd", cmd);
    }
    
	
  if (strcmp (cmd,"Init DB") ==0 || strcmp (cmd, "SHOW TABLES")== 0 || strcmp (cmd,  "SHOW TABLE")==0)
    {
      if ((pThdData->getTHD())->db !=0)
	{
	  yajl_add_string(gen, "objects");
	  yajl_gen_array_open(gen);
	  yajl_add_obj (gen,(pThdData->getTHD())->db,"database", NULL);
	  yajl_gen_array_close(gen);
	}
    }


  if (pLex && command != COM_QUIT && pLex->query_tables)
    {
      yajl_add_string(gen, "objects");
      yajl_gen_array_open(gen);
      TABLE_LIST * table = pLex->query_tables;
      bool isFirstElementInView = true;

      while (table)
        {
	  yajl_gen_map_open(gen);
	  if (isFirstElementInView  && strstr (cmd,"_view")!=NULL )
            {
	      yajl_add_obj (gen,table->get_db_name(), "view",table->get_table_name());
	      isFirstElementInView = false;
            }
	  else 
            {
	      yajl_add_obj (gen,table->get_db_name(), retrive_object_type(table),table->get_table_name());
	    }
	  yajl_gen_map_close(gen);
	  table = table->next_global;
        }
      yajl_gen_array_close(gen);
    }


  size_t qlen = 0;

  const char * query = thd_query(pThdData->getTHD(), &qlen);
  if (query && qlen > 0)
    {
      CHARSET_INFO *col_connection = Item::default_charset();
      if (strcmp (col_connection->csname,"utf8")!=0) {
	String sQuery (query,col_connection) ;
	pThdData->getTHD()->convert_string (&sQuery,col_connection,&my_charset_utf8_general_ci);
	yajl_add_string_val(gen, "query", sQuery.c_ptr_safe(), sQuery.length());
      }
      else
	{
	  yajl_add_string_val(gen, "query",query, qlen);
	}
		
    }
  else 
    {
      if (cmd!=NULL && strlen (cmd)!=0)
        {
	  yajl_add_string_val(gen, "query",cmd, strlen (cmd));
        }
      else 
        {
	  yajl_add_string_val(gen, "query","n/a", strlen ("n/a"    ));
        }
    }
  ssize_t res = -2;
  yajl_gen_status stat = yajl_gen_map_close(gen); //close the object
  if(stat == yajl_gen_status_ok) //all is good write the buffer out
    {
      const unsigned char * text = NULL;
      unsigned int len = 0;
      yajl_gen_get_buf(gen, &text, &len);
      //print the json
      res = writer->write((const char *)text, len);
      if(res >= 0)
        {
	  //TODO: use the msg_delimiter
	  res = writer->write("\n", 1);
        }
      //my_fwrite(log_file, (uchar *) b.data, json_size(&b), MYF(0));
    }
  yajl_gen_free(gen); //free the generator
  return res;
}




ThdSesData::ThdSesData (THD *pTHD) : m_pThd (pTHD), m_CmdName(NULL)
{
  m_CmdName = retrieve_command (m_pThd);    
}
