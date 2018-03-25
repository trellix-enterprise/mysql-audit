AUDIT Plugin for MySQL<sup>*</sup>
===================

A MySQL plugin from McAfee providing audit capabilities for MySQL, 
designed with an emphasis on security and audit requirements. The plugin may be used 
as a standalone audit solution or configured to feed data to external monitoring tools.


Installation and Configuration 
------------------------------

Please check out our wiki on github for detailed installation and configuration instructions:

https://github.com/mcafee/mysql-audit/wiki 


Issues
------------------------------

Found a bug? Got a feature request or question?

Please feel free to report to: https://github.com/mcafee/mysql-audit/issues

If reporting a bug, please describe the problem verbosely. Try to see if it reproduces and 
include a detailed description on how to reproduce.
 
Make sure to include your MySQL Server version and Audit Plugin version.
To print MySQL Server version: log into MySQL and execute the command: 

    status

Please include with the bug the MySQL error log. 
Log file location can be queried by running the following command: 

     show global variables like 'log_error'


Source Code
-------------------------------
Source code is available at: https://github.com/mcafee/mysql-audit

	
License
-------------------------------
Copyright (C) 2011-2018 McAfee, LLC.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU 
General Public License as published by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

See COPYING file for a copy of the GPL Version 2 license.

<sup>*</sup> Other trademarks and brands may be claimed as the property of others.
