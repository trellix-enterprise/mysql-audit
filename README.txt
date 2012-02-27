Audit Plugin

This is a release of Audit Plugin for MySQL 5.1 and 5.5.

Audit Plugin is brought to you by McAfee, Inc (www.mcafee.com). 


==== INSTALLATION =====

Make sure to download the proper binary distribution. There are separate binaries for MySQL 5.1 and 5.5 according
to platform (32 or 64 bit).

Audit Plugin is available in the binary distribution under the lib dir. File name: libaudit_plugin.so.
To install Audit Plugin, copy libaudit_plugin.so to the plugin_dir (for example /usr/lib/mysql/plugin or  /usr/lib64/mysql/plugin) of MySQL. 

To see the configured plugin dir login to MySQL and issue the following command:

show global variables like 'plugin_dir';

There are 2 options for installing the plugin via plugin-load configuration option or by issuing the 
INSTALL PLUGIN statement. 

* Installing via: plugin-load

Add to the MySQL option file (my.cnf) at the [mysqld] section the option: 
plugin-load=AUDIT=libaudit_plugin.so 

Restart the mysqld server for the changes to take effect.

* Installing via: INSTALL PLUGIN

You will need to issue the following sql command to install the plugin:

INSTALL PLUGIN AUDIT SONAME 'libaudit_plugin.so';

A restart to the mysqld server is not necessary.

Note: On production systems, McAfee recommends using the plugin-load option for installing 
the audit plugin.  

More info on installing MySQL plugins is available at: 
http://dev.mysql.com/doc/refman/5.1/en/plugin-installing-uninstalling.html 

===== VERIFICATION =====

To check if the plugin is installed successfully you can issue the following command, which will show all installed plugins:

show plugins;

The Audit plugin will show up with the name AUDIT. 

Additionally you can verify the version of the Audit Plugin by running the following command:

show global status like 'AUDIT_version';


===== CONFIGURATION =====

By default, after installation the Audit Plugin doesn't log activity. You must explicitly enable
the type of logging desired. Configuration is done through the use of MySQL system variables.
Audit Plugin system variables can be set at server startup using options on the command line or in an option file. 
Additionally, the Audit Plugin system variables can be changed dynamically while the server is running 
by means of the SET statement. 

Available Audit Plugin command line options:

--audit-json-file   AUDIT plugin json log file Enable|Disable
--audit-json-file-sync=#
                    AUDIT plugin json log file sync period. If the value of
                    this variable is greater than 0, audit log will sync to
                    disk after every audit_json_file_sync writes.
--audit-json-log-file=name
                    AUDIT plugin json log file name
--audit-json-socket AUDIT plugin json log unix socket Enable|Disable
--audit-json-socket-name=name
                    AUDIT plugin json log unix socket name
--audit-uninstall-plugin
					AUDIT uninstall plugin Enable|Disable. 
					If disabled attempts to uninstall the AUDIT plugin via the sql UNINSTALL command will fail.
					Provides added security from uninstalling the plugin. Also protection from 
					CVE-2010-1621 (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1621) 
					affecting versions upto 5.1.46.
					

===== REPORTING BUGS =====

Please describe the problem verbosely. Try to see if it reproduces and 
include a detailed description on how to reproduce.
 
Make sure to include your MySQL Server version and Audit Plugin version.
To print MySQL Server version log into MySQL and execute the command: status.

Please include with the bug the log files:
 
* mysql-audit.log
* MySQL error log: log file location can be queried by running the following 
	command: show global variables like 'log_error'

	
===== LICENSE =====

The software included in this product contains copyrighted software that is licensed under the GPL Version 2. 
See COPYING file for a copy of the GPL Version 2 license. 
Source code is available at: https://github.com/mcafee/mysql-audit 
