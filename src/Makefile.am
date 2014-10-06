#
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

#pcre dependencies
$(top_srcdir)/pcre/libpcre.la:
	cd $(top_srcdir)/pcre && $(MAKE) $(AM_MAKEFLAGS) libpcre.la

INCLUDES = $(MYSQL_INC) $(YAJL_INC) $(UDIS_INC) -I$(top_srcdir)/pcre
			
pkgplugindir =  $(MYSQL_PLUGIN_DIR)

pkgplugin_LTLIBRARIES =	libaudit_plugin.la

libaudit_plugin_la_DEPENDENCIESADD = pcre

libaudit_plugin_la_LDFLAGS =	-module -Wl,--version-script=MySQLPlugin.map 

libaudit_plugin_la_SOURCES =	hot_patch.cc audit_offsets.cc audit_plugin.cc audit_handler.cc md5.cc

libaudit_plugin_la_LIBADD = $(top_srcdir)/yajl/src/libyajl.la $(top_srcdir)/udis86/libudis86/libudis86.la $(top_srcdir)/pcre/libpcre.la $(MYSQL_LIBSERVICES)  



