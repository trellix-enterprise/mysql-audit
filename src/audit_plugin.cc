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

#include "mysql_inc.h"
#include "hot_patch.h"
#include <stdlib.h>
#include <ctype.h>

#include "audit_handler.h"
#include <string.h>
#include <sys/mman.h>
#if MYSQL_VERSION_ID >= 50600
//in 5.6 md5 implementation changed and we include our own
#include "md5.h"
#endif

/*
 Disable __attribute__() on non-gcc compilers.

 #if !defined(__attribute__) && !defined(__GNUC__)
 #define __attribute__(A)
 #endif
 */

//see offset-extract/readme.txt for explanation on how this was generated
#if !defined(MARIADB_BASE_VERSION)
#ifdef __x86_64__
//64 bit offsets
static const ThdOffsets thd_offsets_arr[] =
{
        //DISTRIBUTION: rpm
		//offsets for: mysqlrpm/5.1.30/usr/sbin/mysqld (5.1.30-community)
		{"5.1.30-community","8e43bda3644a883d46a1d064304b4f1d", 6184, 6248, 3656, 3928, 88, 2048},
		//offsets for: mysqlrpm/5.1.31/usr/sbin/mysqld (5.1.31-community)
		{"5.1.31-community","540d4cf28ea559a0edea0ee971c9a107", 6192, 6256, 3664, 3936, 88, 2040},
		//offsets for: mysqlrpm/5.1.32/usr/sbin/mysqld (5.1.32-community)
		{"5.1.32-community","b75c7d571e9d12b8c37ceafb9042c987", 6192, 6256, 3664, 3936, 88, 2040},
		//offsets for: mysqlrpm/5.1.33/usr/sbin/mysqld (5.1.33-community)
		{"5.1.33-community","56e820a385ff22f732e0638aa262b447", 6192, 6256, 3664, 3936, 88, 2048},
		//offsets for: mysqlrpm/5.1.34/usr/sbin/mysqld (5.1.34-community)
		{"5.1.34-community","da3c0f88578725356b04e7631591bef3", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.35/usr/sbin/mysqld (5.1.35-community)
		{"5.1.35-community","c2676c2496fea6741ebd5df7cf7ce444", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.36/usr/sbin/mysqld (5.1.36-community)
		{"5.1.36-community","3de797ee36be61a8221a6093eb9c649e", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.37/usr/sbin/mysqld (5.1.37-community)
		{"5.1.37-community","508ffea25280c9454dcef065e5fd4af2", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.38/usr/sbin/mysqld (5.1.38-community)
		{"5.1.38-community","3bf0d4cc9fded79b76e5467c1b5dac82", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.39/usr/sbin/mysqld (5.1.39-community)
		{"5.1.39-community","deca5ca3813a9d4157f37f5280be8a26", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.40/usr/sbin/mysqld (5.1.40-community)
		{"5.1.40-community","6ce779a6883b69a1ba28ca5640e60a55", 6200, 6264, 3672, 3944, 88, 2048},
		{"5.1.40-community","2fa8842d7685c8c7d4a1cdd8533d7f62", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.41/usr/sbin/mysqld (5.1.41-community)
		{"5.1.41-community","6ccf4357688d8e46bfcb4443966970b0", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.42/usr/sbin/mysqld (5.1.42-community)
		{"5.1.42-community","8dd9f47e0998958d8826aa2a2487114e", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.43/usr/sbin/mysqld (5.1.43-community)
		{"5.1.43-community","bcd73a2b710327861608fc3d3464f8df", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: mysqlrpm/5.1.44/usr/sbin/mysqld (5.1.44-community)
		{"5.1.44-community","e059b94720daa145d9807a33e9c450b9", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: mysqlrpm/5.1.45/usr/sbin/mysqld (5.1.45-community)
		{"5.1.45-community","7f681b9441bf05f20c4b1b5e7f580269", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: mysqlrpm/5.1.46/usr/sbin/mysqld (5.1.46-community)
		{"5.1.46-community","7e16a80f8593ce5dc65042101c572b9c", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: mysqlrpm/5.1.47/usr/sbin/mysqld (5.1.47-community)
		{"5.1.47-community","8a4de4573d4037cc27adf45ab7275544", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.48/usr/sbin/mysqld (5.1.48-community)
		{"5.1.48-community","10ac2c73ff9476752f15c5658bc3d5ce", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.49/usr/sbin/mysqld (5.1.49-community)
		{"5.1.49-community","85c8cd6984de26580ddf49d87ea76c43", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.50/usr/sbin/mysqld (5.1.50-community)
		{"5.1.50-community","174ce50cfc926bfb04701acdd1d7489d", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.51/usr/sbin/mysqld (5.1.51-community)
		{"5.1.51-community","4ebe71217f34c38fc80c8aa2c4ddcca8", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.52/usr/sbin/mysqld (5.1.52-community)
		{"5.1.52-community","bbb6ca9baf04a4c596e53c49a1e34589", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.53/usr/sbin/mysqld (5.1.53-community)
		{"5.1.53-community","90d9cd7d6c2793e31e42aaa378dbe044", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.54/usr/sbin/mysqld (5.1.54-community)
		{"5.1.54-community","c23b86ac2f64e9de6731fef97e79c98e", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.55/usr/sbin/mysqld (5.1.55-community)
		{"5.1.55-community","e5d0694364a5e14dd227cb3c28ea0928", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.56/usr/sbin/mysqld (5.1.56-community)
		{"5.1.56-community","fd16157ab06cc0cfb3eba40e9936792c", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: /usr/sbin/mysqld (5.1.56-ndb-7.1.18-cluster-gpl)
		{"5.1.56-ndb-7.1.18-cluster-gpl","ee9cc4dd2f0e9db04dce32867fcf599e", 6304, 6368, 3640, 3912, 88, 2048},
		//offsets for: mysqlrpm/5.1.57/usr/sbin/mysqld (5.1.57-community)
		{"5.1.57-community","4c6d32f80c20657983f7ac316c6a6e10", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: mysqlrpm/5.1.58/usr/sbin/mysqld (5.1.58-community)
		{"5.1.58-community","e42752084a90c708a94779d26589b748", 6336, 6400, 3688, 3960, 88, 2048},
        {"5.1.58-community","032d4f14464851e724281f8b692578a2", 6336, 6400, 3688, 3960, 88, 2048},
        //offsets for: /usr/sbin/mysqld (5.1.58-community)
		{"5.1.58-community","7c51a8f1aabece893982e0cafac8dcee", 6336, 6400, 3688, 3960, 88, 2048},
		//offsets for: /mysqlrpm/5.1.59/usr/sbin/mysqld (5.1.59-community)
        {"5.1.59-community","9463387bf70c07376a52a93bf44c51f0", 6328, 6392, 3688, 3960, 88, 2048},
        //offsets for: /mysqlrpm/5.1.60/usr/sbin/mysqld (5.1.60-community)
        {"5.1.60-community","d9497964e8983a348538c0d05eaee7f0", 6328, 6392, 3688, 3960, 88, 2048},
        //offsets for: /mysqlrpm/5.1.61/usr/sbin/mysqld (5.1.61-community)
        {"5.1.61-community","bda6030d35e7fafa5b1e57154a53b804", 6328, 6392, 3688, 3960, 88, 2048},
		//offsets for: /mysqlrpm/5.1.62/usr/sbin/mysqld (5.1.62-community)
		{"5.1.62-community","a4e8de89e0d9a353d09687d3b4560cb3", 6328, 6392, 3688, 3960, 88, 2048},
		//offsets for: /mysqlrpm/5.1.63/usr/sbin/mysqld (5.1.63-community)
		{"5.1.63-community","0f4d7e3b17eb36f17aafe4360993a769", 6328, 6392, 3688, 3960, 88, 2048},
		//offsets for: /mysqlrpm/5.1.65/usr/sbin/mysqld (5.1.65-community)
		{"5.1.65-community","4df4c0dfe11913bd1ef2bb3a6bc7a40e", 6376, 6440, 3736, 4008, 88, 2056},
		//offsets for: /mysqlrpm/5.1.66/usr/sbin/mysqld (5.1.66-community)
		{"5.1.66-community","544ed94102b82425e7592e7d7474fce4", 6376, 6440, 3736, 4008, 88, 2056},
		//offsets for: /mysqlrpm/5.1.67/usr/sbin/mysqld (5.1.67-community)
		{"5.1.67-community","f67df6f2416940dbabff460b83b63677", 6376, 6440, 3736, 4008, 88, 2056},
		//offsets for: /mysqlrpm/5.1.68/usr/sbin/mysqld (5.1.68-community)
		{"5.1.68-community","4042e9a2778090df6fd8481e03ed6737", 6376, 6440, 3736, 4008, 88, 2056},
		//offsets for: /mysqlrpm/5.1.69/usr/sbin/mysqld (5.1.69-community)
		{"5.1.69-community","e9cb524b604419964f4dd55a8c87d618", 6376, 6440, 3736, 4008, 88, 2056},
		
        //offsets for: mysqlrpm/5.5.8/usr/sbin/mysqld (5.5.8)
        {"5.5.8","70a882693d54df8ab7c7d9f256e317bb", 6032, 6080, 3776, 4200, 88, 2560},
        //offsets for: mysqlrpm/5.5.9/usr/sbin/mysqld (5.5.9)
        {"5.5.9","262554c75df0b890e08c5c2500391342", 6056, 6104, 3800, 4224, 88, 2560},
        //offsets for: mysqlrpm/5.5.10/usr/sbin/mysqld (5.5.10)
        {"5.5.10","f9d15e7ff70ad177923b9d2a14b9bc19", 6056, 6104, 3800, 4224, 88, 2560},
        //offsets for: mysqlrpm/5.5.11/usr/sbin/mysqld (5.5.11)
        {"5.5.11","04a7049ba1c099e00dcdc6f1d98078aa", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.12/usr/sbin/mysqld (5.5.12)
        {"5.5.12","91df7918803df78b164f46706003e22d", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.13/usr/sbin/mysqld (5.5.13)
        {"5.5.13","f13cbe2c1a5247c52d592ac199b8d9af", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.14/usr/sbin/mysqld (5.5.14)
        {"5.5.14","4fb94eac7eaa2dc9bbf3ee773a54197e", 6048, 6096, 3792, 4216, 88, 2560},
        {"5.5.15-debug", "", 6256, 6304, 3992, 4424, 88, 2560},
        //offsets for: mysqlrpm/5.5.15/usr/sbin/mysqld (5.5.15)
        {"5.5.15","d3c2a51a84cbec77c2fb92f1ea414ec3", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.16/usr/sbin/mysqld (5.5.16)
        {"5.5.16","289c64d14b132c67fd22cd6404817bc3", 6040, 6088, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.17/usr/sbin/mysqld (5.5.17)
        {"5.5.17","9c6b2f65b1015f924fb74408d2968339", 6040, 6088, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.18/usr/sbin/mysqld (5.5.18)
        {"5.5.18","60d191bfeea1232e86fa4ad54ae46b10", 6040, 6088, 3792, 4216, 88, 2560},
        {"5.5.18","099d31c0cd0754934b84c17f683d019e", 6040, 6088, 3792, 4216, 88, 2560},
        //offsets for: mysqlrpm/5.5.19/usr/sbin/mysqld (5.5.19)
        {"5.5.19","0765dadb23315bb076bc6e21cfb2de40", 6048, 6096, 3800, 4224, 88, 2560},
        //offsets for: /mysqlrpm/5.5.20/usr/sbin/mysqld (5.5.20)
        {"5.5.20","9f6122576930c5d09ca9244094c83f24", 6048, 6096, 3800, 4224, 88, 2560},
        //offsets for: mysqlrpm/5.5.21/usr/sbin/mysqld (5.5.21)
        {"5.5.21","4a03ad064ed393dabdde175f3ea05ff2", 6048, 6096, 3800, 4224, 88, 2560},
		//offsets for percona rpm (redhat 6): /usr/sbin/mysqld (5.5.21-55)
		{"5.5.21-55","e4f1b39e9dca4edc51b8eb6aa09e2fa4", 6464, 6512, 4072, 4512, 88, 2576},
		//offsets for: mysqlrpm/5.5.22/usr/sbin/mysqld (5.5.22)
		{"5.5.22","f3592147108e65d92cb18fb4d900c4ab", 6048, 6096, 3800, 4224, 88, 2560},
		//offsets for: Percona-Server-server-55-5.5.22-rel25.2.237.rhel5.x86_64/usr/sbin/mysqld (5.5.22-55)
		{"5.5.22-55","0865d71ff0159d3f79f7e277e6010f92", 6456, 6504, 4064, 4504, 104, 2576},
		//offsets for: mysqlrpm/5.5.23/usr/sbin/mysqld (5.5.23)
		{"5.5.23","aac33433f75b9758e7f42fad6991fa9e", 6048, 6096, 3800, 4224, 88, 2568},
		//offsets for: mysqlrpm/5.5.24/usr/sbin/mysqld (5.5.24)
		{"5.5.24","2915a9dd079446149b17d0d1c478fb11", 6048, 6096, 3800, 4224, 88, 2568},
		//offsets for: /mysqlrpm/5.5.25/usr/sbin/mysqld (5.5.25)
		{"5.5.25","6043eff2cfa493d4e020cae65c41b030", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: mysqlrpm/5.5.25a/usr/sbin/mysqld (5.5.25a)
		{"5.5.25a","b59c03244daf51d4327409288d8c889f", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysqlrpm/5.5.27/usr/sbin/mysqld (5.5.27)
		{"5.5.27","8a3bd2ea1db328f4443fc25a79450ff3", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysqlrpm/5.5.28/usr/sbin/mysqld (5.5.28)
		{"5.5.28","588a710a1aec3043203261af72a13219", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysqlrpm/5.5.29/usr/sbin/mysqld (5.5.29)
		{"5.5.29","c1991059f9db3e4d5f23f34d9ff9c1d5", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: cluster-7.2.10-linux-rhel5-x86-64bit/cluster/bin/mysqld (5.5.29-ndb-7.2.10-cluster-commercial-advanced-log)
		{"5.5.29-ndb-7.2.10-cluster-commercial-advanced","7fae09caa49af8bced6d250587cc2fcb", 6088, 6136, 3808, 4232, 88, 2568},
		//offsets for: /mysqlrpm/5.5.30/usr/sbin/mysqld (5.5.30)
		{"5.5.30","2c92adf1c8c4cef089bd487a56d72288", 6064, 6112, 3816, 4240, 88, 2568},
		//offsets for: mysql-cluster-advanced-7.2.12-linux2.6-x86_64/bin/mysqld (5.5.30-ndb-7.2.12-cluster-commercial-advanced)
		{"5.5.30-ndb-7.2.12-cluster-commercial-advanced","9f96bc38bf06a9b18a945227ff9e5c42", 6096, 6144, 3816, 4240, 88, 2568},
		//offsets for: /mysqlrpm/5.5.31/usr/sbin/mysqld (5.5.31)
		{"5.5.31","f6604e70b9592f484a7a04a0173f0b25", 6064, 6112, 3816, 4240, 88, 2568},
		
		//offsets for: MySQL-server-5.6.10-1.el6.x86_64/usr/sbin/mysqld (5.6.10)
		{"5.6.10","7016428728fe057d6825682d30e37b3d", 7808, 7856, 3960, 4400, 72, 2664},
		//offsets for: /mysqlrpm/5.6.10/usr/sbin/mysqld (5.6.10)
		{"5.6.10","3b34d181e1d9baa4534fe1146ceb0ce9", 7808, 7856, 3960, 4400, 72, 2664},
		//offsets for: /mysqlrpm/5.6.11/usr/sbin/mysqld (5.6.11)
		{"5.6.11","452f9bb49741bfc97d0266120016d77b", 7808, 7856, 3960, 4400, 72, 2672},
        //offsets for: /usr/sbin/mysqld (5.6.12)
        {"5.6.12","8ec14d79a5fcb0e9a55b5e4da39b9896", 7816, 7864, 3960, 4400, 72, 2688},

				//DISTRIBUTION: tar.gz
		//offsets for: /mysql/5.1.30/bin/mysqld (5.1.30)
		{"5.1.30","b301b32be659367c1a1900b47534fd59", 6192, 6256, 3664, 3936, 88, 2048},
		//offsets for: /mysql/5.1.31/bin/mysqld (5.1.31)
		{"5.1.31","2d8be9bf479678b3f2bd3214f1f04c7e", 6200, 6264, 3672, 3944, 88, 2040},
		//offsets for: /mysql/5.1.32/bin/mysqld (5.1.32)
		{"5.1.32","c585253cf70944471c936962a318a81a", 6200, 6264, 3672, 3944, 88, 2040},
		//offsets for: /mysql/5.1.33/bin/mysqld (5.1.33)
		{"5.1.33","99d8cbc22dc2919abe530ed61a52c89d", 6200, 6264, 3672, 3944, 88, 2048},
		//offsets for: /mysql/5.1.34/bin/mysqld (5.1.34)
		{"5.1.34","47b8eb2e619dd953e4ce6cf468a19c6e", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.35/bin/mysqld (5.1.35)
		{"5.1.35","950a25d0a4e4e100b72d60ffd451e93a", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.36/bin/mysqld (5.1.36)
		{"5.1.36","758c2ac0375425a43cd815d3a2c10132", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.37/bin/mysqld (5.1.37)
		{"5.1.37","4e7bfc2705eea482a19b710944dc5ff5", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.38/bin/mysqld (5.1.38)
		{"5.1.38","09e8ac98651439fd4f22b508178cd0ef", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.39/bin/mysqld (5.1.39)
		{"5.1.39","b6c4acb0a9a4ff71ab5e26ed010d20c9", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.40/bin/mysqld (5.1.40)
		{"5.1.40","bc663cdf0a8411526dc9eb44dff5773f", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.41/bin/mysqld (5.1.41)
		{"5.1.41","ebf47135d6fe9099cd62db1dea2c4ca6", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.42/bin/mysqld (5.1.42)
		{"5.1.42","a7b55239789304978d8250697a3c73fc", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.43/bin/mysqld (5.1.43)
		{"5.1.43","96e95d0b1461f4484e571af01c01bc4a", 6208, 6272, 3680, 3952, 88, 2048},
		//offsets for: /mysql/5.1.44/bin/mysqld (5.1.44)
		{"5.1.44","ecf6919ce6d4e74d108644ab122ff1fb", 6216, 6280, 3688, 3960, 88, 2048},
		//offsets for: /mysql/5.1.45/bin/mysqld (5.1.45)
		{"5.1.45","657c7e712a894ebe3b3db9b26cc3ebd7", 6216, 6280, 3688, 3960, 88, 2048},
		//offsets for: /mysql/5.1.46/bin/mysqld (5.1.46)
		{"5.1.46","990b3bafe5d55dc1a9084791623191ca", 6216, 6280, 3688, 3960, 88, 2048},
		//offsets for: /mysql/5.1.47/bin/mysqld (5.1.47)
		{"5.1.47","9868b07a44f8d5de8bc5716e3f680139", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.48/bin/mysqld (5.1.48)
		{"5.1.48","e812133194ff8e0cd25945c327e07f6c", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.49/bin/mysqld (5.1.49)
		{"5.1.49","4869d51b5bfc38f7698059e2696a95ca", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.50/bin/mysqld (5.1.50)
		{"5.1.50","316a6b674d66cb151bac384cb0508357", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.51/bin/mysqld (5.1.51)
		{"5.1.51","b9f831f698cd7fa85abe112bb99c8861", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.52/bin/mysqld (5.1.52)
		{"5.1.52","c31f9c5d042e8793b3f192fa04f0e628", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.53/bin/mysqld (5.1.53)
		{"5.1.53","07a3ae20e262306e708760889ff2705b", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.54/bin/mysqld (5.1.54)
		{"5.1.54","9fca5d956c33e646920e68c541aabcae", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.55/bin/mysqld (5.1.55)
		{"5.1.55","54457f3bc49d7ac7497f4212538c8ddc", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.56/bin/mysqld (5.1.56)
		{"5.1.56","1a901cb4c1ff55aeab04ba4ba9e5f4ec", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.57/bin/mysqld (5.1.57)
		{"5.1.57","c3c4f7c4403e501b11c532fb4eccf68b", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.58/bin/mysqld (5.1.58)
		{"5.1.58","3e93f9d332fb8e3b9481f4620361f481", 6344, 6408, 3696, 3968, 88, 2048},
        {"5.1.58","5620fefe93dbc46cb2d488a054d2e81a", 6344, 6408, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.59/bin/mysqld (5.1.59)
        {"5.1.59","61fe56a6bcd71a9ea6026322f459555b", 6336, 6400, 3696, 3968, 88, 2048},
        //offsets for: /mysql/5.1.60/bin/mysqld (5.1.60)
        {"5.1.60","5407e492f802cca03eccb2211205632d", 6336, 6400, 3696, 3968, 88, 2048},
        //offsets for: /mysql/5.1.61/bin/mysqld (5.1.61)
        {"5.1.61","c2ce56446b33ee22c16160b3f8206541", 6336, 6400, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.62/bin/mysqld (5.1.62)
		{"5.1.62","5ab9ae376d93b71120e1c9dc2129c580", 6336, 6400, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.63/bin/mysqld (5.1.63)
		{"5.1.63","ea56cc85859f146c42957177524492c3", 6336, 6400, 3696, 3968, 88, 2048},
		//offsets set by https://github.com/creechy
		{"5.1.63","2a6d7c81179baf6bc6bbb807b8b54967", 6336, 6400, 3696, 3968, 88, 2048},
		//offsets for: /mysql/5.1.65/bin/mysqld (5.1.65)
		{"5.1.65","65d905e173c06316b736ee4e9be15baf", 6392, 6456, 3752, 4024, 88, 2056},
		//offsets for: /mysql/5.1.66/bin/mysqld (5.1.66)
		{"5.1.66","2cd9a97779d436d1d5d045eb12620ef0", 6392, 6456, 3752, 4024, 88, 2056},
		//offsets for: /mysql/5.1.67/bin/mysqld (5.1.67)
		{"5.1.67","a33947226f24f59d30e7c40c61d840ca", 6392, 6456, 3752, 4024, 88, 2056},
		//offsets for: /mysql/5.1.68/bin/mysqld (5.1.68)
		{"5.1.68","673dd031ea4ad3493b47d74662a49079", 6392, 6456, 3752, 4024, 88, 2056},
		//offsets for: /mysql/5.1.69/bin/mysqld (5.1.69)
		{"5.1.69","af2936f85db019bfd44c7e12a2138707", 6392, 6456, 3752, 4024, 88, 2056},

        //offsets for: mysql/5.5.8/bin/mysqld (5.5.8)
        {"5.5.8","a32b163f08ca8bfd7486cd77200d9df3", 6032, 6080, 3776, 4200, 88, 2560},
        //offsets for: mysql/5.5.9/bin/mysqld (5.5.9)
        {"5.5.9","7b01c8b42a47f3541ee62b1e3f1b7816", 6056, 6104, 3800, 4224, 88, 2560},
        //offsets for: mysql/5.5.10/bin/mysqld (5.5.10)
        {"5.5.10","de2bb7a3fa3cea8c3aae9e0c544ab8f4", 6056, 6104, 3800, 4224, 88, 2560},
        //offsets for: mysql/5.5.11/bin/mysqld (5.5.11)
        {"5.5.11","cc565bd5de75d86ccf9371789afa3a15", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.12/bin/mysqld (5.5.12)
        {"5.5.12","a37a096e0c6afa81d023368434432a70", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.13/bin/mysqld (5.5.13)
        {"5.5.13","299abd40c9b5cf9421083aeddc8cfb66", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.14/bin/mysqld (5.5.14)
        {"5.5.14","98c716bb1ad38cf018d881dbf578fade", 6048, 6096, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.15/bin/mysqld (5.5.15)
        {"5.5.15","73a45e429c63542efbb70bcf56d869be", 6048, 6096, 3792, 4216, 88, 2560},
        {"5.5.15-debug","",  6256, 6304, 3992, 4424, 88, 2560},
        //offsets for: mysql/5.5.16/bin/mysqld (5.5.16)
        {"5.5.16","9f4b0b7f721a0d57822c3e7417dec532", 6040, 6088, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.17/bin/mysqld (5.5.17)
        {"5.5.17","1998ce51314f86b587891dd80db067d6", 6040, 6088, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.18/bin/mysqld (5.5.18)
        {"5.5.18","d0a874863943e837a685e7fc4af02a87", 6040, 6088, 3792, 4216, 88, 2560},
        //offsets for: mysql/5.5.19/bin/mysqld (5.5.19)
        //offsets for: /usr/sbin/mysqld (5.5.18)
        {"5.5.18","099d31c0cd0754934b84c17f683d019e", 6040, 6088, 3792, 4216, 88, 2560},
        {"5.5.19","f000f941c4e4f7b84e66d7b8c115ca8f", 6048, 6096, 3800, 4224, 88, 2560},
        //offsets for: /mysql/5.5.20/bin/mysqld (5.5.20)
        {"5.5.20","8b68e84332b442d58a46ae4299380a99", 6048, 6096, 3800, 4224, 88, 2560},
        //offsets for: mysql/5.5.21/bin/mysqld (5.5.21)
        {"5.5.21","66d23cb577e2bcfe29da08833f5e7d8b", 6048, 6096, 3800, 4224, 88, 2560},
		//offsets for percona: Percona-Server-5.5.21-rel25.0-227.Linux.x86_64/bin/mysqld (5.5.21-rel25.0)
		{"5.5.21-rel25.0","346a87d97dbf5d7aad3a9f7f707f9477", 6464, 6512, 4072, 4512, 88, 2576},
		//offsets for: /mysql/5.5.22/bin/mysqld (5.5.22)
		{"5.5.22","9152de65a0de0594f46e1db0d0c9a182", 6048, 6096, 3800, 4224, 88, 2560},
		//offsets for: /mysql/5.5.23/bin/mysqld (5.5.23)
		{"5.5.23","da3c9d8e3bf1c1235d283cbfad1631ab", 6048, 6096, 3800, 4224, 88, 2568},
		//offsets for: /mysql/5.5.24/bin/mysqld (5.5.24)
		{"5.5.24","5cb90eb8d4080f50fd7a432ad9eb75e0", 6048, 6096, 3800, 4224, 88, 2568},
		//offsets for: /mysql/5.5.25/bin/mysqld (5.5.25)
		{"5.5.25","3c19465f6b6f2daecb7a2d7ac1592824", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysql/5.5.27/bin/mysqld (5.5.27)
		{"5.5.27","0c6d305da14143ac17bf8964243234a4", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysql/5.5.28/bin/mysqld (5.5.28)
		{"5.5.28","8fbd19126907af43440baa4584dc7d28", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysql/5.5.29/bin/mysqld (5.5.29)
		{"5.5.29","495fc2576127ab851baa1ebb39a8f6fe", 6056, 6104, 3808, 4232, 88, 2568},
		//offsets for: /mysql/5.5.30/bin/mysqld (5.5.30)
		{"5.5.30","a2a8aba9c124315c17634556a303f87a", 6064, 6112, 3816, 4240, 88, 2568},
		//offsets for: MySQL-server-5.5.31-2.rhel5.x86_64/usr/sbin/mysqld (5.5.31)
		{"5.5.31","858dc19ffc5d34e669ab85d32a8a0623", 6064, 6112, 3816, 4240, 88, 2568},
		//offsets for: /mysql/5.5.31/bin/mysqld (5.5.31)
		{"5.5.31","61e65a4cc9360e03f3810ef2928c916d", 6064, 6112, 3816, 4240, 88, 2568},

		//offsets for: /mysql/5.6.10/bin/mysqld (5.6.10)
		{"5.6.10","37f9c31dd092bb2d0da7eb6e2098732f", 7808, 7856, 3960, 4400, 72, 2664},
		//offsets for: /mysql/5.6.11/bin/mysqld (5.6.11)
		{"5.6.11","85fd884192cc5cd12fba52b7b140c819", 7808, 7856, 3960, 4400, 72, 2672},
		
		//offsets for: /mysqlrpm/5.1.70/usr/sbin/mysqld (5.1.70-community)
		{"5.1.70-community","e70f9d48dad2a30b24e6c2744bed94d2", 6376, 6440, 3736, 4008, 88, 2072},
		//offsets for: /mysqlrpm/5.5.32/usr/sbin/mysqld (5.5.32)
		{"5.5.32","0a8f2dab859c59656a7ee18f1c97746b", 6064, 6112, 3816, 4240, 88, 2592},
		//offsets for: /mysqlrpm/5.6.12/usr/sbin/mysqld (5.6.12)
		{"5.6.12","647c61f9e2e42a6b8af67ad7f3268858", 7816, 7864, 3960, 4400, 72, 2688},
		//offsets for: /mysql/5.1.70/bin/mysqld (5.1.70)
		{"5.1.70","67b86b3ffff1196ac6702a89cd41ff84", 6392, 6456, 3752, 4024, 88, 2072},
		//offsets for: /mysql/5.5.32/bin/mysqld (5.5.32)
		{"5.5.32","97829c2915124a7cfa605d3f39bea354", 6064, 6112, 3816, 4240, 88, 2592},
		//offsets for: /mysql/5.6.12/bin/mysqld (5.6.12)
		{"5.6.12","3a6bb81a7f1239eb810a06a3b0c5dc2a", 7816, 7864, 3960, 4400, 72, 2688},
        //offsets for: /mysqlrpm/5.1.71/usr/sbin/mysqld (5.1.71-community) 
		{"5.1.71-community","c8453ca637925c878356ca43eef8f654", 6376, 6440, 3736, 4008, 88, 2072},
		//offsets for: /mysqlrpm/5.5.33/usr/sbin/mysqld (5.5.33) 
		{"5.5.33","88b02a9e61f5faedcf2d64a9b0239f38", 6064, 6112, 3816, 4240, 88, 2592},
		//offsets for: /mysqlrpm/5.6.13/usr/sbin/mysqld (5.6.13) 
		{"5.6.13","441bbd39cf3df4847289f4cd4b2b3dc3", 7816, 7864, 3960, 4400, 72, 2688},
		//offsets for: /mysql/5.1.71/bin/mysqld (5.1.71) 
		{"5.1.71","f648e9c956c85fbb1fbe8250df518755", 6392, 6456, 3752, 4024, 88, 2072},
		//offsets for: /mysql/5.5.33/bin/mysqld (5.5.33) 
		{"5.5.33","59bf9fe80d6005e38238bc083b5aef51", 6064, 6112, 3816, 4240, 88, 2592},
		//offsets for: /mysql/5.6.13/bin/mysqld (5.6.13) 
		{"5.6.13","137c18e72cfe17d4fcacda209e405234", 7816, 7864, 3960, 4400, 72, 2688},
		//offsets for: /mysql-5.5.34-linux2.6-x86_64/bin/mysqld (5.5.34)
		{"5.5.34","94d083ef0a7f964dedb94684eb06c7e7", 6136, 6184, 3816, 4312, 88, 2592, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.5.34/usr/sbin/mysqld (5.5.34) 
		{"5.5.34","b146111cae431cbb3d20322cc0a8e3be", 6136, 6184, 3816, 4312, 88, 2592, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.6.14/usr/sbin/mysqld (5.6.14) 
		{"5.6.14","42907ed406036f7d651a73547a611be0", 7888, 7936, 3960, 4472, 72, 2696, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.1.72/usr/sbin/mysqld (5.1.72-community) 
		{"5.1.72-community","c53f0d8b4d400755e8c476cd512dcea3", 6384, 6448, 3736, 4008, 88, 2072, 8, 0, 24, 16},
		//offsets for: /mysql/5.1.72/bin/mysqld (5.1.72) 
		{"5.1.72","f560445d3c5f98a88d50878b2cd661c0", 6400, 6464, 3752, 4024, 88, 2072, 8, 0, 24, 16},
		//offsets for: /mysqlrpm/5.1.73/usr/sbin/mysqld (5.1.73-community) 
		{"5.1.73-community","85cdb461556846fb29cbbaae49dfde94", 6384, 6448, 3736, 4008, 88, 2072, 8, 0, 24, 16},
		//offsets for: /mysqlrpm/5.5.35/usr/sbin/mysqld (5.5.35) 
		{"5.5.35","09c5971f9df91d9fde18e969f66d9ff7", 6136, 6184, 3816, 4312, 88, 2592, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.6.15/usr/sbin/mysqld (5.6.15) 
		{"5.6.15","dbd2d20241e4e59412b5d2bff97513da", 7920, 7968, 3984, 4504, 72, 2704, 96, 0, 32, 104},
		//offsets for: /mysql/5.1.73/bin/mysqld (5.1.73) 
		{"5.1.73","c84e4519e1ada16c245a87170bf1c3f0", 6400, 6464, 3752, 4024, 88, 2072, 8, 0, 24, 16},
		//offsets for: /mysqlrpm/5.5.36/usr/sbin/mysqld (5.5.36) 
		{"5.5.36","c88f67a152a2f9d74b8fd3ef182418be", 6136, 6184, 3816, 4312, 88, 2592, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.6.16/usr/sbin/mysqld (5.6.16) 
		{"5.6.16","5f5ef8d06a3ead4f0bfa2e43edc69898", 7920, 7968, 3984, 4504, 72, 2704, 96, 0, 32, 104},
		//offsets for: /mysql/5.5.36/bin/mysqld (5.5.36) 
		{"5.5.36","f5595334dd163428d54a546b11b8e205", 6136, 6184, 3816, 4312, 88, 2592, 96, 0, 32, 104},
		//offsets for: /mysql/5.6.16/bin/mysqld (5.6.16) 
		{"5.6.16","b50b5c83341099b9cd6f6749dfd71bca", 7920, 7968, 3984, 4504, 72, 2704, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.6.17/usr/sbin/mysqld (5.6.17) 
		{"5.6.17","972845b7f80376956fc1db46ec88f72e", 7928, 7976, 3992, 4512, 72, 2704, 96, 0, 32, 104},
		//offsets for: /mysql/5.6.17/bin/mysqld (5.6.17) 
		{"5.6.17","525a28e1f7b05b2b03111f5f521b428d", 7928, 7976, 3992, 4512, 72, 2704, 96, 0, 32, 104},
		//offsets for: /mysqlrpm/5.5.37/usr/sbin/mysqld (5.5.37) 
		{"5.5.37","1a2d5e421f97381578cf037b69e90200", 6136, 6184, 3816, 4312, 88, 2592, 96, 0, 32, 104}
};

#else
//32 bit offsets
static const ThdOffsets thd_offsets_arr[] =
{
        //DISTRIBUTION: rpm
		//offsets for: mysqlrpm/5.1.30/usr/sbin/mysqld (5.1.30-community)
		{"5.1.30-community","fdfe108d05c262c185a7c28b2e493c10", 4024, 4064, 2224, 2404, 44, 1180},
		//offsets for: mysqlrpm/5.1.31/usr/sbin/mysqld (5.1.31-community)
		{"5.1.31-community","79e595a948564164886471fce7b90414", 4028, 4068, 2228, 2408, 44, 1172},
		//offsets for: mysqlrpm/5.1.32/usr/sbin/mysqld (5.1.32-community)
		{"5.1.32-community","08bbc180f9aed54f3b8fb596360766cd", 4028, 4068, 2228, 2408, 44, 1172},
		//offsets for: mysqlrpm/5.1.33/usr/sbin/mysqld (5.1.33-community)
		{"5.1.33-community","c9c3d4de320bbf721a13b0f2d7469a0d", 4032, 4072, 2228, 2408, 44, 1176},
		//offsets for: mysqlrpm/5.1.34/usr/sbin/mysqld (5.1.34-community)
		{"5.1.34-community","806598500d6b9264dcd78eb6f0ed037b", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.35/usr/sbin/mysqld (5.1.35-community)
		{"5.1.35-community","b4202f285a39dc8875fb718e1310c2cd", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.36/usr/sbin/mysqld (5.1.36-community)
		{"5.1.36-community","76dd39a6a4bd61313745b984c186caa2", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.37/usr/sbin/mysqld (5.1.37-community)
		{"5.1.37-community","615173a7021b143a65c31d0e58d01172", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.38/usr/sbin/mysqld (5.1.38-community)
		{"5.1.38-community","f818189713bb56ccce507a4db4fcbfed", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.39/usr/sbin/mysqld (5.1.39-community)
		{"5.1.39-community","9951b3c9c050a9a5e0a2994295e0aa0c", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.40/usr/sbin/mysqld (5.1.40-community)
		{"5.1.40-community","3f44d47492e746e57883fb44e7f92195", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.41/usr/sbin/mysqld (5.1.41-community)
		{"5.1.41-community","b03f583f769bf2638170a157835baffb", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.42/usr/sbin/mysqld (5.1.42-community)
		{"5.1.42-community","ec01163698da7c64e9267e2e4b87133d", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.43/usr/sbin/mysqld (5.1.43-community)
		{"5.1.43-community","dc93f6b2f35e4b7c6814dc39e6bdf7f4", 4036, 4076, 2232, 2412, 44, 1176},
		//offsets for: mysqlrpm/5.1.44/usr/sbin/mysqld (5.1.44-community)
		{"5.1.44-community","cd6f166239d377423533400bf7b00ea3", 4040, 4080, 2236, 2416, 44, 1176},
		//offsets for: mysqlrpm/5.1.45/usr/sbin/mysqld (5.1.45-community)
		{"5.1.45-community","8dcfe0e4adfad351d33f0939442480f6", 4040, 4080, 2236, 2416, 44, 1176},
		//offsets for: mysqlrpm/5.1.46/usr/sbin/mysqld (5.1.46-community)
		{"5.1.46-community","5e2689bea4fbccceed1e32cd96cc3c34", 4040, 4080, 2236, 2416, 44, 1176},
		//offsets for: mysqlrpm/5.1.47/usr/sbin/mysqld (5.1.47-community)
		{"5.1.47-community","d24830298658630ff57c28e886f7867a", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.48/usr/sbin/mysqld (5.1.48-community)
		{"5.1.48-community","0fb5da11cb2af69c9c8ccb4e7e09c2ba", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.49/usr/sbin/mysqld (5.1.49-community)
		{"5.1.49-community","44c5f411e0ca0251afed127c2eab099a", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.50/usr/sbin/mysqld (5.1.50-community)
		{"5.1.50-community","ba318e3ea6c628e771c061bc8f8fd747", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.51/usr/sbin/mysqld (5.1.51-community)
		{"5.1.51-community","9e3294ed95b2f1197466f3b4100074b4", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.52/usr/sbin/mysqld (5.1.52-community)
        {"5.1.52-community","6bef5cbe540f8a5d445b9ae243a0d228", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.53/usr/sbin/mysqld (5.1.53-community)
		{"5.1.53-community","cd34abf1b7cc20928a30b23c9270bae9", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.54/usr/sbin/mysqld (5.1.54-community)
		{"5.1.54-community","af4e3ed1f31aba894714bb9dd572b920", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.55/usr/sbin/mysqld (5.1.55-community)
		{"5.1.55-community","3b201091f1f87ec89c0f69b5e5712cd5", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.56/usr/sbin/mysqld (5.1.56-community)
		{"5.1.56-community","43fb22017f5fb7ba436dbf53fe45ac5d", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.57/usr/sbin/mysqld (5.1.57-community)
    	{"5.1.57-community","b3b137aaa9550b070185e7fb1b788a97", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: mysqlrpm/5.1.58/usr/sbin/mysqld (5.1.58-community)
		{"5.1.58-community","728f80ea4a231f85b2dc8661bf6828fc", 4104, 4144, 2240, 2420, 44, 1176},
        {"5.1.58-community","a4199c1595d0ef3f0b1a2ffbc4e74976", 4104, 4144, 2240, 2420, 44, 1176},
        {"5.1.58-community","5d9be93190a88860d0d4f4033c2d3d09", 4104, 4144, 2240, 2420, 44, 1176},
        {"5.1.58-community","5b7a9bca308184339999f42db6224467", 4104, 4144, 2240, 2420, 44, 1176},
		//offsets for: /mysqlrpm/5.1.59/usr/sbin/mysqld (5.1.59-community)
        {"5.1.59-community","2405f0bf32c0a1439a157e54431443de", 4096, 4136, 2240, 2420, 44, 1176},
        //offsets for: /mysqlrpm/5.1.60/usr/sbin/mysqld (5.1.60-community)
        {"5.1.60-community","bc2d74ea58d22d998f8f8c88139fc5f7", 4096, 4136, 2240, 2420, 44, 1176},
         //offsets for: /mysqlrpm/5.1.61/usr/sbin/mysqld (5.1.61-community)
        {"5.1.61-community","f73013eb2001a02c84ddd0ac42a307ac", 4096, 4136, 2240, 2420, 44, 1176},
		//offsets for: /mysqlrpm/5.1.62/usr/sbin/mysqld (5.1.62-community)
		{"5.1.62-community","f410638e7414c6cc709b7d5cda24669c", 4096, 4136, 2240, 2420, 44, 1176},
		//offsets for: /mysqlrpm/5.1.63/usr/sbin/mysqld (5.1.63-community)
		{"5.1.63-community","2b39264a67466c6f1dfa37c37a8a6bd0", 4096, 4136, 2240, 2420, 44, 1176},
		//offsets for: /mysqlrpm/5.1.65/usr/sbin/mysqld (5.1.65-community)
		{"5.1.65-community","0e96922fe95be696f7f91fc5a94c5d46", 4124, 4164, 2268, 2448, 44, 1180},
		//offsets for: /mysqlrpm/5.1.66/usr/sbin/mysqld (5.1.66-community)
		{"5.1.66-community","60049b5c82e3479323001ffb28447820", 4124, 4164, 2268, 2448, 44, 1180},
		//offsets for: /mysqlrpm/5.1.67/usr/sbin/mysqld (5.1.67-community)
		{"5.1.67-community","2ca1d344c7054644a7e98c34b11bee64", 4124, 4164, 2268, 2448, 44, 1180},
		//offsets for: /mysqlrpm/5.1.68/usr/sbin/mysqld (5.1.68-community)
		{"5.1.68-community","df5dc268b36dbe853ed37d91fd4b6b3f", 4124, 4164, 2268, 2448, 44, 1180},
		//offsets for: /mysqlrpm/5.1.69/usr/sbin/mysqld (5.1.69-community)
		{"5.1.69-community","4c8acbca31f3f4ba44d35db9f5c65bc0", 4124, 4164, 2268, 2448, 44, 1180},
		
        //offsets for: mysqlrpm/5.5.8/usr/sbin/mysqld (5.5.8)
        {"5.5.8","3132e8c883f72caf4c8eddb24fd005b4", 3792, 3820, 2336, 2668, 44, 1640},
        //offsets for: mysqlrpm/5.5.9/usr/sbin/mysqld (5.5.9)
        {"5.5.9","1f9f8f5109687db75c15bc04d4396842", 3816, 3844, 2360, 2692, 44, 1640},
        //offsets for: mysqlrpm/5.5.10/usr/sbin/mysqld (5.5.10)
        {"5.5.10","f9e6ef8075fe370842c0fce571eac6e1", 3816, 3844, 2360, 2692, 44, 1640},
        //offsets for: mysqlrpm/5.5.11/usr/sbin/mysqld (5.5.11)
        {"5.5.11","37c160fac1cc844fc4aa09bb23a60022", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.12/usr/sbin/mysqld (5.5.12)
        {"5.5.12","565093ea45815edd8fa8bd444825aa6d", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.13/usr/sbin/mysqld (5.5.13)
        {"5.5.13","0592c10129e360623a70bbcc1618c7ad", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.14/usr/sbin/mysqld (5.5.14)
        {"5.5.14","53eca2f96ec9185c1b733c2b254fa416", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.15/usr/sbin/mysqld (5.5.15)
        {"5.5.15","01fa6e9c9eafb638c801cc3d261dca70", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.16/usr/sbin/mysqld (5.5.16)
        {"5.5.16","0959bb8b5a0fa940c900873ff743bd59", 3804, 3832, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.17/usr/sbin/mysqld (5.5.17)
        {"5.5.17","c99b809e13c52ac0e173baff0df24f75", 3804, 3832, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.18/usr/sbin/mysqld (5.5.18)
        {"5.5.18","bbeb7e7ad983ea1db87665d8e530f6b6", 3804, 3832, 2356, 2688, 44, 1640},
        //offsets for: mysqlrpm/5.5.19/usr/sbin/mysqld (5.5.19)
        {"5.5.19","f3c31e2a5d95d3511b7106441f38929e", 3808, 3836, 2360, 2692, 44, 1640},
        //offsets for: /mysqlrpm/5.5.20/usr/sbin/mysqld (5.5.20)
        {"5.5.20","c73100bcb0d967b627cad72e66503194", 3808, 3836, 2360, 2692, 44, 1640},
        //offsets for: mysqlrpm/5.5.21/usr/sbin/mysqld (5.5.21)
        {"5.5.21","18d78ced97227b83e62e9b43ba5b3883", 3808, 3836, 2360, 2692, 44, 1640},
		//offsets for: /mysqlrpm/5.5.22/usr/sbin/mysqld (5.5.22)
		{"5.5.22","9da3081f83069a2762831d0ead5a97c8", 3808, 3836, 2360, 2692, 44, 1640},
		//offsets for: /mysqlrpm/5.5.23/usr/sbin/mysqld (5.5.23)
		{"5.5.23","c94f20f31cfa674d5763da7d2344c219", 3808, 3836, 2360, 2692, 44, 1644},
		//offsets for: /mysqlrpm/5.5.24/usr/sbin/mysqld (5.5.24)
		{"5.5.24","10e0ced8d28daf6a9c16d2b57be7c6af", 3808, 3836, 2360, 2692, 44, 1644},
		//offsets for: /mysqlrpm/5.5.25/usr/sbin/mysqld (5.5.25)
		{"5.5.25","bd20af37978967a145724098e913eeda", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysqlrpm/5.5.27/usr/sbin/mysqld (5.5.27)
		{"5.5.27","e6a9760303ea8fdd4face5a88d925059", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysqlrpm/5.5.28/usr/sbin/mysqld (5.5.28)
		{"5.5.28","8f435a5b9308fd2c4d20860fb3b38ec7", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysqlrpm/5.5.29/usr/sbin/mysqld (5.5.29)
		{"5.5.29","89c4df6dcf941ccded0c08c73d976877", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysqlrpm/5.5.30/usr/sbin/mysqld (5.5.30)
		{"5.5.30","0186d1ef4725814924bfe968e3455138", 3816, 3844, 2368, 2700, 44, 1644},
		//offsets for: /mysqlrpm/5.5.31/usr/sbin/mysqld (5.5.31)
		{"5.5.31","190e7556e226f8690ba8672869178e4c", 3816, 3844, 2368, 2700, 44, 1644},

		//offsets for: /mysqlrpm/5.6.10/usr/sbin/mysqld (5.6.10)
		{"5.6.10","dd3abddcfd0015de81b6a26b6190cefb", 5572, 5600, 2640, 2980, 36, 1712},
		//offsets for: /mysqlrpm/5.6.11/usr/sbin/mysqld (5.6.11)
		{"5.6.11","0f716b88d1c11c031dbb206a3e1b31a4", 5572, 5600, 2640, 2980, 36, 1724},

        //DISTRIBUTION: tar.gz
		//offsets for: mysql/5.1.30/bin/mysqld (5.1.30)
		{"5.1.30","f02d15a37e8e7513e7570023b48ccb4d", 4028, 4068, 2228, 2408, 44, 1180},
		//offsets for: mysql/5.1.31/bin/mysqld (5.1.31)
		{"5.1.31","a3a240c57429f67c4fcb5c960d30f5cc", 4036, 4076, 2236, 2416, 44, 1172},
		//offsets for: mysql/5.1.32/bin/mysqld (5.1.32)
		{"5.1.32","b8d4491363c8b4e4fb61fce807cb849c", 4036, 4076, 2236, 2416, 44, 1172},
		//offsets for: mysql/5.1.33/bin/mysqld (5.1.33)
		{"5.1.33","1b8c93710fe908565cf434b8a4a472c6", 4040, 4080, 2236, 2416, 44, 1176},
		//offsets for: mysql/5.1.34/bin/mysqld (5.1.34)
		{"5.1.34","dcbd60d1c75bcb75b75bf0428b64bcfa", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.35/bin/mysqld (5.1.35)
		{"5.1.35","ffd1fa84e00daace393e5450298fcbeb", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.36/bin/mysqld (5.1.36)
		{"5.1.36","3a45ab0b7d8bcac42933b8635b7898ef", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.37/bin/mysqld (5.1.37)
		{"5.1.37","fb51c158439a1a2524048822f803b900", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.38/bin/mysqld (5.1.38)
		{"5.1.38","3325969a0feffd660968ff489d59e648", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.39/bin/mysqld (5.1.39)
		{"5.1.39","e3c3f1ab7d6f11d4db161f76e01ae229", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.40/bin/mysqld (5.1.40)
		{"5.1.40","f068b9eef84e76556e90889148011911", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.41/bin/mysqld (5.1.41)
		{"5.1.41","dcfa2d28d2bb193d8883bf0f465582db", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.42/bin/mysqld (5.1.42)
		{"5.1.42","f384b97929c2cef7cfe292cc2d1ed018", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.43/bin/mysqld (5.1.43)
		{"5.1.43","10035c4e3877da190d6f2b00c3f28eea", 4044, 4084, 2240, 2420, 44, 1176},
		//offsets for: mysql/5.1.44/bin/mysqld (5.1.44)
		{"5.1.44","5119573ff0a4ad1688a5ac6412b5b51a", 4048, 4088, 2244, 2424, 44, 1176},
		//offsets for: mysql/5.1.45/bin/mysqld (5.1.45)
		{"5.1.45","8a57e78f7b0bf6818ba032c05a4b5c6b", 4048, 4088, 2244, 2424, 44, 1176},
		//offsets for: mysql/5.1.46/bin/mysqld (5.1.46)
		{"5.1.46","090c3c45fbe7a37fa83b1567604d9598", 4048, 4088, 2244, 2424, 44, 1176},
		//offsets for: mysql/5.1.47/bin/mysqld (5.1.47)
		{"5.1.47","1864a85030c04e85dc9c9c37db449e11", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.48/bin/mysqld (5.1.48)
		{"5.1.48","73a8915a1549012fcfeefe285f9dda3b", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.49/bin/mysqld (5.1.49)
		{"5.1.49","cc318106e6d7670c2e0d787c61c64e3e", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.50/bin/mysqld (5.1.50)
		{"5.1.50","d651dd6ba898bb6fe4b94a820f6bc670", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.51/bin/mysqld (5.1.51)
		{"5.1.51","bc5b02298ab8f928c57055a1ddf9f9eb", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.52/bin/mysqld (5.1.52)
		{"5.1.52","1553d70d4a1e50cbc3372cfc19c781d1", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.53/bin/mysqld (5.1.53)
		{"5.1.53","c9e447344659169b6a94c24b30872539", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.54/bin/mysqld (5.1.54)
		{"5.1.54","bf71b8a6a3ba8d1dccae9173d1b24f1c", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.55/bin/mysqld (5.1.55)
		{"5.1.55","9fad028c88f5236d6d573b49d228cfbd", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.56/bin/mysqld (5.1.56)
		{"5.1.56","01ed5d208a836a81770a9b4cf7e3c950", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.57/bin/mysqld (5.1.57)
		{"5.1.57","e180e87ea25ddf3834a6f397e56e6df6", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: mysql/5.1.58/bin/mysqld (5.1.58)
		{"5.1.58","46795902e2a8a54976e3c4fd81cb567f", 4112, 4152, 2248, 2428, 44, 1176},
        {"5.1.58","3200476a63ce76810171d6791fdfb1fe", 4112, 4152, 2248, 2428, 44, 1176},
		//offsets for: /mysql/5.1.59/bin/mysqld (5.1.59)
        {"5.1.59","3122bfbeea3e4b420be996eb64244fb4", 4104, 4144, 2248, 2428, 44, 1176},
        //offsets for: /mysql/5.1.60/bin/mysqld (5.1.60)
        {"5.1.60","520270041d8c490d49233e88741c025c", 4104, 4144, 2248, 2428, 44, 1176},
        //offsets for: /mysql/5.1.61/bin/mysqld (5.1.61)
        {"5.1.61","1a7a0981d77f4d212e899efaa581bd42", 4104, 4144, 2248, 2428, 44, 1176},		
		//offsets for: /mysql/5.1.62/bin/mysqld (5.1.62)
		{"5.1.62","4c5fd81faa9fe407c8a7fbd11b29351a", 4104, 4144, 2248, 2428, 44, 1176},
		//offsets for: /mysql/5.1.63/bin/mysqld (5.1.63)
		{"5.1.63","576124febe6310985e432f6346031ff4", 4104, 4144, 2248, 2428, 44, 1176},
		//offsets for: /mysql/5.1.65/bin/mysqld (5.1.65)
		{"5.1.65","96c750de824898f8af435bd7b73a5e88", 4140, 4180, 2284, 2464, 44, 1180},
		//offsets for: /mysql/5.1.66/bin/mysqld (5.1.66)
		{"5.1.66","db5aea9077c989e079980960405807bc", 4140, 4180, 2284, 2464, 44, 1180},
		//offsets for: /mysql/5.1.67/bin/mysqld (5.1.67)
		{"5.1.67","9f2609f5925abe6f3c01a05a53569b35", 4140, 4180, 2284, 2464, 44, 1180},
		//offsets for: /mysql/5.1.68/bin/mysqld (5.1.68)
		{"5.1.68","d03c42d8a8946f11ace86a5e1189114d", 4140, 4180, 2284, 2464, 44, 1180},
		//offsets for: /mysql/5.1.69/bin/mysqld (5.1.69)
		{"5.1.69","5abf5a9f9f9c01be997595b066a40986", 4140, 4180, 2284, 2464, 44, 1180},
		
		//offsets for: /mysqlrpm/5.5.8/usr/sbin/mysqld (5.5.8)
		{"5.5.8","3132e8c883f72caf4c8eddb24fd005b4", 3792, 3820, 2336, 2668, 44, 1640},
        {"5.5.8","ad8a16d9bbfb783dab53f38cef757900", 3792, 3820, 2336, 2668, 44, 1640},
        //offsets for: /mysql/5.5.8/bin/mysqld (5.5.8)
        {"5.5.8","9fad75a10170625712be354ec5b52f2d", 3792, 3820, 2336, 2668, 44, 1640},
        //offsets for: /mysql/5.5.9/bin/mysqld (5.5.9)
        {"5.5.9","6ff8ac441ea0e5ff90dc95a47443ea8c", 3816, 3844, 2360, 2692, 44, 1640},
        //offsets for: /mysql/5.5.10/bin/mysqld (5.5.10)
        {"5.5.10","f27715ede95269b83527338739184f49", 3816, 3844, 2360, 2692, 44, 1640},
        //offsets for: /mysql/5.5.11/bin/mysqld (5.5.11)
        {"5.5.11","896bf69c3b42fb77e9efdd5fd3661800", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.12/bin/mysqld (5.5.12)
        {"5.5.12","c95e1181fadd0a04fe2c7a153058b6f3", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.13/bin/mysqld (5.5.13)
        {"5.5.13","d22b9d5bccd9f8bdb3158a87edd0992e", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.14/bin/mysqld (5.5.14)
        {"5.5.14","e77fa342d52bd3a7cbd551b8a9649e40", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.15/bin/mysqld (5.5.15)
        {"5.5.15","f070920da92c8fdf920f516bfbf7cbb4", 3812, 3840, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.16/bin/mysqld (5.5.16)
        {"5.5.16","291c0f871da9691a2271d48e79d7cf2b", 3804, 3832, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.17/bin/mysqld (5.5.17)
        {"5.5.17","64fde4494dbdd3e05457df5ac93c7760", 3804, 3832, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.18/bin/mysqld (5.5.18)
        {"5.5.18","5f6f2516ff4728f3b04613ed66233aa5", 3804, 3832, 2356, 2688, 44, 1640},
        //offsets for: /mysql/5.5.19/bin/mysqld (5.5.19)
        {"5.5.19","b407d678b9b855bfd29ba3c9f014d4b0", 3808, 3836, 2360, 2692, 44, 1640},
        //offsets for: /mysql/5.5.20/bin/mysqld (5.5.20)
        {"5.5.20","cb9b6887ea525fe9965121d357163fe4", 3808, 3836, 2360, 2692, 44, 1640},
        //offsets for: mysql/5.5.21/bin/mysqld (5.5.21)
        {"5.5.21","a0762cee3ad5d4e77480956144900213", 3808, 3836, 2360, 2692, 44, 1640},
		//offsets for: /mysql/5.5.22/bin/mysqld (5.5.22)
		{"5.5.22","f635047c7ddf74dcac98612a65e40fe1", 3808, 3836, 2360, 2692, 44, 1640},
		//offsets for: /mysql-5.5_5.5.22-0ubuntu1_i386/bin/mysqld (5.5.22-0ubuntu1)
		{"5.5.22-0ubuntu1","9cc7d4582b1fae0ebf43dbe5ffb56008", 3784, 3812, 2336, 2668, 44, 1640},
		//offsets for: /mysql/5.5.23/bin/mysqld (5.5.23)
		{"5.5.23","8f51987d3f0d0dc044adcf42937050f6", 3808, 3836, 2360, 2692, 44, 1644},
		//offsets for: /mysql/5.5.24/bin/mysqld (5.5.24)
		{"5.5.24","a3916dca234905bd49b3fefe5d6ad738", 3808, 3836, 2360, 2692, 44, 1644},
		//offsets for: /mysql/5.5.25/bin/mysqld (5.5.25)
		{"5.5.25","f16c3fa53f77e5f25fd25694b5a27c48", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysql/5.5.27/bin/mysqld (5.5.27)
		{"5.5.27","b4d8ccf9348ecfe52fcf1d34b37a394d", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysql/5.5.28/bin/mysqld (5.5.28)
		{"5.5.28","f8922e4289a17acf0347e478f6f30705", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysql/5.5.29/bin/mysqld (5.5.29)
		{"5.5.29","e94a673a244449de87e6a489a7a08acb", 3812, 3840, 2364, 2696, 44, 1644},
		//offsets for: /mysql/5.5.30/bin/mysqld (5.5.30)
		{"5.5.30","c7b98be45d35b77da6679c354c23d1fa", 3816, 3844, 2368, 2700, 44, 1644},
		//offsets for: /mysql/5.5.31/bin/mysqld (5.5.31)
		{"5.5.31","36631a7c748358598ba21cd4157545d9", 3816, 3844, 2368, 2700, 44, 1644},
		
		//offsets for: /mysql/5.6.10/bin/mysqld (5.6.10)
		{"5.6.10","84600f18354f519e38302c04fe55ed9c", 5572, 5600, 2640, 2980, 36, 1712},
		//offsets for: /mysql/5.6.11/bin/mysqld (5.6.11)
		{"5.6.11","72e67111f3c1d1c1d4e7095e3a004fcf", 5572, 5600, 2640, 2980, 36, 1724},
		
		//offsets for: /mysqlrpm/5.1.70/usr/sbin/mysqld (5.1.70-community)
		{"5.1.70-community","605c76c9d37a890cea85c075aeaaa2e6", 4124, 4164, 2268, 2448, 44, 1188},
		//offsets for: /mysqlrpm/5.5.32/usr/sbin/mysqld (5.5.32)
		{"5.5.32","3c00829c6ef3286598079b9f49de9843", 3816, 3844, 2368, 2700, 44, 1656},
		//offsets for: /mysqlrpm/5.6.12/usr/sbin/mysqld (5.6.12)
		{"5.6.12","edaf494ffda685fb4b03b3d9366f6af6", 5580, 5608, 2640, 2980, 36, 1732},		
		//offsets for: /mysql/5.1.70/bin/mysqld (5.1.70)
		{"5.1.70","f1c06fde306a5cd5b195425c18c4351b", 4140, 4180, 2284, 2464, 44, 1188},
		//offsets for: /mysql/5.5.32/bin/mysqld (5.5.32)
		{"5.5.32","85199d7a643bf0c336385f613b007018", 3816, 3844, 2368, 2700, 44, 1656},
		//offsets for: /mysql/5.6.12/bin/mysqld (5.6.12)
		{"5.6.12","469ed6bc745eea0d47a69ecf7b3e0d56", 5580, 5608, 2640, 2980, 36, 1732},
		//offsets for: /mysqlrpm/5.1.71/usr/sbin/mysqld (5.1.71-community) 
		{"5.1.71-community","2039eb1fb90b85d3744e3628b3ab35fa", 4124, 4164, 2268, 2448, 44, 1188},
		//offsets for: /mysqlrpm/5.5.33/usr/sbin/mysqld (5.5.33) 
		{"5.5.33","403fe8f9ecd935890f7ebc73297a08bb", 3816, 3844, 2368, 2700, 44, 1656},
		//offsets for: /mysqlrpm/5.6.13/usr/sbin/mysqld (5.6.13) 
		{"5.6.13","8ac0185b8f8a2a066ed0f5cd45597d6b", 5580, 5608, 2640, 2980, 36, 1732},
		//offsets for: /mysql/5.1.71/bin/mysqld (5.1.71) 
		{"5.1.71","5e9120167eae0138de4e6f307f337383", 4140, 4180, 2284, 2464, 44, 1188},
		//offsets for: /mysql/5.5.33/bin/mysqld (5.5.33) 
		{"5.5.33","3172729c5bf6e81c8d87fe26fe248204", 3816, 3844, 2368, 2700, 44, 1656},
		//offsets for: /mysql/5.6.13/bin/mysqld (5.6.13) 
		{"5.6.13","f25a8fabbb1d205f0f2d772d7f41b9da", 5580, 5608, 2640, 2980, 36, 1732},
		//offsets for: /mysqlrpm/5.5.34/usr/sbin/mysqld (5.5.34) 
		{"5.5.34","fc8bc7c4edd6c115be5f941ca4618f63", 3868, 3896, 2368, 2748, 44, 1656, 60, 0, 20, 64},
		//offsets for: /mysqlrpm/5.6.14/usr/sbin/mysqld (5.6.14) 
		{"5.6.14","d7444b6db9d1a5aceb2162e77de762dc", 5632, 5660, 2640, 3028, 36, 1744, 60, 0, 20, 64},
		//offsets for: /mysqlrpm/5.1.72/usr/sbin/mysqld (5.1.72-community) 
		{"5.1.72-community","3f7221660b8c9e953f327da95d250597", 4128, 4168, 2268, 2448, 44, 1188, 4, 0, 12, 8},
		//offsets for: /mysql/5.1.72/bin/mysqld (5.1.72) 
		{"5.1.72","199d47e26e5a4cc29399724f47c30aca", 4144, 4184, 2284, 2464, 44, 1188, 4, 0, 12, 8},
		//offsets for: /mysqlrpm/5.1.73/usr/sbin/mysqld (5.1.73-community) 
		{"5.1.73-community","3ecceab3ca6a816f5744a9437208e5a3", 4128, 4168, 2268, 2448, 44, 1188, 4, 0, 12, 8},
		//offsets for: /mysqlrpm/5.5.35/usr/sbin/mysqld (5.5.35) 
		{"5.5.35","7cd5543273a70209e746b6df7d4b5406", 3868, 3896, 2368, 2748, 44, 1656, 60, 0, 20, 64},
		//offsets for: /mysqlrpm/5.6.15/usr/sbin/mysqld (5.6.15) 
		{"5.6.15","59683562fb382b2ab43394517802595e", 5648, 5676, 2652, 3044, 36, 1748, 60, 0, 20, 64},
		//offsets for: /mysql/5.1.73/bin/mysqld (5.1.73) 
		{"5.1.73","6a9357091496248e25387f9c2c0c75c4", 4144, 4184, 2284, 2464, 44, 1188, 4, 0, 12, 8},
		//offsets for: /mysqlrpm/5.5.36/usr/sbin/mysqld (5.5.36) 
		{"5.5.36","361590c58e15541246b6d3dbc46011da", 3868, 3896, 2368, 2748, 44, 1656, 60, 0, 20, 64},
		//offsets for: /mysqlrpm/5.6.16/usr/sbin/mysqld (5.6.16) 
		{"5.6.16","5a570b87913b8d028dfdfca3fc82bd19", 5648, 5676, 2652, 3044, 36, 1748, 60, 0, 20, 64},
		//offsets for: /mysql/5.5.36/bin/mysqld (5.5.36) 
		{"5.5.36","22663b7989f3c24619493ac414cbca38", 3868, 3896, 2368, 2748, 44, 1656, 60, 0, 20, 64},
		//offsets for: /mysql/5.6.16/bin/mysqld (5.6.16) 
		{"5.6.16","7019959ebb4adaff1047aa4dfb1ff688", 5648, 5676, 2652, 3044, 36, 1748, 60, 0, 20, 64},
		//offsets for: /mysqlrpm/5.6.17/usr/sbin/mysqld (5.6.17) 
		{"5.6.17","c2a9a665cb88d59b21d85236c963a814", 5652, 5680, 2656, 3048, 36, 1748, 60, 0, 20, 64},
		//offsets for: /mysql/5.6.17/bin/mysqld (5.6.17) 
		{"5.6.17","fc472182fa82c4e6a2e84fa3e6550bc9", 5652, 5680, 2656, 3048, 36, 1748, 60, 0, 20, 64},
		//offsets for: /mysqlrpm/5.5.37/usr/sbin/mysqld (5.5.37) 
		{"5.5.37","4f7f6578b33b23ae04aa5c8b13a335dc", 3868, 3896, 2368, 2748, 44, 1656, 60, 0, 20, 64}
};

#endif


#else
//start offsets for MariaDB
#ifdef __x86_64__
//64 bit offsets
static const ThdOffsets thd_offsets_arr[] =
{	
	//offsets for: /mariadb/5.5.32/bin/mysqld (5.5.32-MariaDB) 
	{"5.5.32-MariaDB","c67c5c5eaab8467ad1cc170db8e0492d", 12032, 12096, 5816, 6912, 88, 2928, 8, 0, 16, 24},
	//offsets for: /mariadb/5.5.33/bin/mysqld (5.5.33-MariaDB) 
	{"5.5.33-MariaDB","170f56b89ca6a263c625b9f6dd76c6ad", 12032, 12096, 5816, 6912, 88, 2928, 8, 0, 16, 24},
	//offsets for: /mariadb/5.5.33a/bin/mysqld (5.5.33a-MariaDB) 
	{"5.5.33a-MariaDB","dc57899efbcc93a0ddf57c1820acf351", 12032, 12096, 5816, 6912, 88, 2928, 8, 0, 16, 24},
	//offsets for: /mariadb/5.5.34/bin/mysqld (5.5.34-MariaDB) 
	{"5.5.34-MariaDB","0c6901e6e213142c3db5176af4329696", 12032, 12096, 5816, 6912, 88, 2928, 8, 0, 16, 24},
	//offsets for: /mariadb/5.5.35/bin/mysqld (5.5.35-MariaDB) 
	{"5.5.35-MariaDB","18b283a98fa3659cf667446850e338eb", 12040, 12104, 5824, 6920, 88, 2936, 8, 0, 16, 24},	
	//offsets for: /mariadb/5.5.36/bin/mysqld (5.5.36-MariaDB) 
	{"5.5.36-MariaDB","33180ec22cf201f6f769540538318b5b", 12040, 12104, 5824, 6920, 88, 2936, 8, 0, 16, 24}
};

#else
//32 bit offsets
static const ThdOffsets thd_offsets_arr[] =
{	
	//offsets for: /mariadb/5.5.32/bin/mysqld (5.5.32-MariaDB) 
	{"5.5.32-MariaDB","1c523e9b505795636319e30151eaf022", 7288, 7324, 3476, 4480, 44, 1856, 4, 0, 8, 12},
	//offsets for: /mariadb/5.5.33/bin/mysqld (5.5.33-MariaDB) 
	{"5.5.33-MariaDB","0cdf83696aabc4cba2e9642c3b986f6d", 7288, 7324, 3476, 4480, 44, 1856, 4, 0, 8, 12},
	//offsets for: /mariadb/5.5.33a/bin/mysqld (5.5.33a-MariaDB) 
	{"5.5.33a-MariaDB","6b7fa32fe316e16e3adba2fd2940a976", 7288, 7324, 3476, 4480, 44, 1856, 4, 0, 8, 12},
	//offsets for: /mariadb/5.5.34/bin/mysqld (5.5.34-MariaDB) 
	{"5.5.34-MariaDB","13639243e755ca61e45e61cd92c860b2", 7288, 7324, 3476, 4480, 44, 1856, 4, 0, 8, 12},
	//offsets for: /mariadb/5.5.35/bin/mysqld (5.5.35-MariaDB) 
	{"5.5.35-MariaDB","1dc4e9caca4b9aa2440943ba3355a572", 7296, 7332, 3484, 4488, 44, 1860, 4, 0, 8, 12},
	//offsets for: /mariadb/5.5.36/bin/mysqld (5.5.36-MariaDB) 
	{"5.5.36-MariaDB","5cf95a64e10e2b53b8c85554874d034b", 7296, 7332, 3484, 4488, 44, 1860, 4, 0, 8, 12}
};
#endif

//end offsets for MariaDB
#endif


static my_bool need_free_memalloc_plugin_var = FALSE;

static const char * log_prefix = AUDIT_LOG_PREFIX;

//possible audit handlers
static Audit_file_handler json_file_handler;
static Audit_socket_handler json_socket_handler;

//formatters
static Audit_json_formatter json_formatter;

//flags to hold if audit handlers are enabled
static my_bool json_file_handler_enable = FALSE;
static my_bool json_file_handler_flush = FALSE;
static my_bool json_socket_handler_enable = FALSE;
static my_bool uninstall_plugin_enable = FALSE;
static my_bool validate_checksum_enable = FALSE;
static my_bool offsets_by_version_enable = FALSE;
static my_bool validate_offsets_extended_enable = FALSE;
static char * offsets_string = NULL;
static char * checksum_string = NULL;
static int delay_ms_val =0;
static char *delay_cmds_string = NULL;
static char *record_cmds_string = NULL;
static char *record_objs_string = NULL;
static char *whitelist_users_string = NULL;

static char delay_cmds_array [SQLCOM_END + 2][MAX_COMMAND_CHAR_NUMBERS] = {{0}};
static char record_cmds_array [SQLCOM_END + 2][MAX_COMMAND_CHAR_NUMBERS] = {{0}};
static char record_objs_array [MAX_NUM_OBJECT_ELEM + 2][MAX_OBJECT_CHAR_NUMBERS] = {{0}};
static char whitelist_users_array [MAX_NUM_USER_ELEM + 2][MAX_USER_CHAR_NUMBERS] = {{0}};
static bool record_empty_objs_set = true;
static int num_delay_cmds = 0;
static int num_record_cmds = 0;
static int num_record_objs = 0;
static int num_whitelist_users = 0;
static SHOW_VAR com_status_vars_array [MAX_COM_STATUS_VARS_RECORDS] = {{0}};
/**
 * The trampoline functions we use. Will be set to point to allocated mem.
 */
static int (*trampoline_mysql_execute_command)(THD *thd) = NULL;
static unsigned int trampoline_mysql_execute_size =0;

#if MYSQL_VERSION_ID < 50600
static void (*trampoline_log_slow_statement)(THD *thd) = NULL;
static unsigned int trampoline_log_slow_statement_size =0;
#endif

#if MYSQL_VERSION_ID < 50505
static int (*trampoline_check_user)(THD *thd, enum enum_server_command command, const char *passwd, uint passwd_len, const char *db, bool check_count) = NULL;
static unsigned int trampoline_check_user_size =0;
#elif MYSQL_VERSION_ID < 50600
static bool (*trampoline_acl_authenticate)(THD *thd, uint connect_errors, uint com_change_user_pkt_len) = NULL;
static unsigned int trampoline_acl_authenticate_size =0;
#endif

static MYSQL_THDVAR_ULONG(is_thd_printed_list,
	PLUGIN_VAR_READONLY | PLUGIN_VAR_NOSYSVAR | PLUGIN_VAR_NOCMDOPT, 	"avoid duplicate printing",
NULL, NULL,0,0,
#ifdef __x86_64__
0xffffffffffffff,
#else
0xffffffff,
#endif 
1);

static MYSQL_THDVAR_ULONG(query_cache_table_list,
    PLUGIN_VAR_READONLY | PLUGIN_VAR_NOSYSVAR | PLUGIN_VAR_NOCMDOPT,    "Pointer to query cache table list.",
NULL, NULL,0,0,
#ifdef __x86_64__
0xffffffffffffff,
#else
0xffffffff,
#endif
1);

THDPRINTED * GetThdPrintedList (THD *thd)
{
    THDPRINTED * pThdPrintedList= (THDPRINTED*)THDVAR(thd,is_thd_printed_list);
    if (pThdPrintedList)
    {
        return pThdPrintedList;
    }
    THDVAR(thd,is_thd_printed_list) =0;
    return NULL;
 }

static int check_array(const char *cmds[],const char *array, int length) {
  for (int k=0; array[k * length] !='\0';k++) {
    for (int q = 0; cmds[q] != NULL; q++) {
      const char *cmd = cmds[q];
      int j = 0;
      while (array[k * length + j] != '\0' && cmd[j] != '\0'
              && array[k * length + j] == tolower(cmd[j])) {
        j++;
      }
      if (array[k * length + j] == '\0' && j != 0) {
        return 1;
      }
    }
  }
  return 0;
}

//utility method checks if the passed db object is part of record_objs_array
static bool check_db_obj(const char * db, const char * name)
{
    char db_obj[MAX_OBJECT_CHAR_NUMBERS] = {0};
    char wildcard_obj[MAX_OBJECT_CHAR_NUMBERS] = {0};
    char db_wildcard[MAX_OBJECT_CHAR_NUMBERS] = {0};
    if(db && name &&
      ((strlen(db) + strlen(name)) < MAX_OBJECT_CHAR_NUMBERS - 2))
    {
        strcpy(db_obj, db);
        strcat(db_obj, ".");
        strcat(db_obj, name);
        strcpy(wildcard_obj, "*.");
        strcat(wildcard_obj, name);
        strcpy(db_wildcard, db);
        strcat(db_wildcard, ".*");
        const char *objects[4];
        objects[0] = db_obj;
        objects[1] = wildcard_obj;
        objects[2] = db_wildcard;
        objects[3] = NULL;
        return check_array(objects, (char *) record_objs_array, MAX_OBJECT_CHAR_NUMBERS);
    }
    return false;
}

static void audit(ThdSesData *pThdData)
{
    THDPRINTED *pThdPrintedList = GetThdPrintedList (pThdData->getTHD());
  if (num_record_cmds > 0) {
      const char * cmd = pThdData->getCmdName();
      const char *cmds[2];
      cmds[0] = cmd;
      cmds[1] = NULL;
      if (!check_array(cmds, (char *) record_cmds_array, MAX_COMMAND_CHAR_NUMBERS)) {
	return;
      }
  }
 if (num_whitelist_users > 0) {
      const char * user = pThdData->getUserName(); //If name is present, then no need to log the query
      const char *users[2];
	  if(NULL == user || '\0' == user[0]) //empty user use special symbol: "{}"
	  {
		user = "{}";
	  }
      users[0] = user;
      users[1] = NULL;
      if (check_array(users, (char *) whitelist_users_array, MAX_USER_CHAR_NUMBERS)) {
	return;
      }
  }
  if (num_record_objs > 0) {
	bool matched = false;
	if(pThdData->startGetObjects())
    {
        const char * db_name = NULL;
        const char * obj_name = NULL;        
        while(!matched && pThdData->getNextObject(&db_name, &obj_name, NULL))
        {
            matched = check_db_obj(db_name, obj_name);
        }        
    }
	else //no objects
	{
		matched = record_empty_objs_set;
	}    
    if (!matched) {
		return;
    }
  }
    if (pThdPrintedList && pThdPrintedList->cur_index  < MAX_NUM_QUEUE_ELEM)
    {
		//audit the event if we haven't done so yet or in the case of prepare_sql we audit as the test "test select" doesn't go through mysql_execute_command
        if (pThdPrintedList->is_thd_printed_queue[pThdPrintedList->cur_index] == 0 || strcmp(pThdData->getCmdName(), "prepare_sql") == 0)
        {
            Audit_handler::log_audit_all(pThdData);
            pThdPrintedList->is_thd_printed_queue[pThdPrintedList->cur_index] = 1;
        }
		else //duplicate no need to audit then simply return
		{
			return;
		}
    }
    else 
    {
        Audit_handler::log_audit_all(pThdData);    
	}
	if (delay_ms_val > 0) 
	{
		const char * cmd = pThdData->getCmdName();
      const char *cmds[2];
      cmds[0] = cmd;
      cmds[1] = NULL;
      int delay = check_array(cmds, (char *) delay_cmds_array, MAX_COMMAND_CHAR_NUMBERS);
      if (delay)
			{
				//Audit_file_handler::print_sleep(thd,delay_ms_val);
				my_sleep (delay_ms_val *1000);
			}
		}
}


static int  (*trampoline_send_result_to_client)(Query_cache *pthis, THD *thd, char *sql, uint query_length) = NULL;

#if MYSQL_VERSION_ID > 50505
static bool (*trampoline_open_tables)(THD *thd, TABLE_LIST **start, uint *counter, uint flags,
                Prelocking_strategy *prelocking_strategy) = NULL;
#else
static int (*trampoline_open_tables)(THD *thd, TABLE_LIST **start, uint *counter, uint flags) = NULL;
#endif


QueryTableInf * Audit_formatter::getQueryCacheTableList1 (THD *thd)
{

	return (QueryTableInf*)	THDVAR(thd, query_cache_table_list);
}

static bool (*trampoline_check_table_access)(THD *thd, ulong want_access,TABLE_LIST *tables,  uint number, bool no_errors) = NULL;

static bool audit_check_table_access(THD *thd, ulong want_access,TABLE_LIST *tables,
	uint number, bool no_errors)
{
	TABLE_LIST *pTables;
	bool res = trampoline_check_table_access (thd, want_access, tables, number, no_errors);
	if (!res &&  tables)
	{
		pTables = tables;
		QueryTableInf * pQueryTableInf =(QueryTableInf*) THDVAR (thd,query_cache_table_list);
		if (pQueryTableInf)
		{
			while (pTables)
			{
				if (pQueryTableInf->num_of_elem < MAX_NUM_QUERY_TABLE_ELEM && pQueryTableInf->num_of_elem>=0)
				{
					pQueryTableInf->db[pQueryTableInf->num_of_elem] = (char*) thd_alloc (thd, strlen(Audit_formatter::table_get_db_name(pTables))+1);
					strcpy (pQueryTableInf->db[pQueryTableInf->num_of_elem],Audit_formatter::table_get_db_name(pTables));
					pQueryTableInf->table_name[pQueryTableInf->num_of_elem] = (char*) thd_alloc (thd, strlen(Audit_formatter::table_get_name(pTables)) +1);
					strcpy (pQueryTableInf->table_name[pQueryTableInf->num_of_elem],Audit_formatter::table_get_name(pTables));
					pQueryTableInf->object_type[pQueryTableInf->num_of_elem] = Audit_formatter::retrieve_object_type ( pTables);					
					pQueryTableInf->num_of_elem ++;
				}
				pTables = pTables->next_global;
			}

		}	
	}
	return res;
}

static unsigned int trampoline_check_table_access_size = 0;

static int  audit_send_result_to_client(Query_cache *pthis, THD *thd, char *sql, uint query_length)
{
	 int res;
	 void *pList = thd_alloc (thd, sizeof (QueryTableInf));
	 

	if (pList)
	 {
		  memset (pList,0,sizeof (QueryTableInf));
		  THDVAR(thd, query_cache_table_list) =(ulong)pList;
	 }	 
	 res = trampoline_send_result_to_client (pthis,thd, sql, query_length);
	 if (res)
	 {
         ThdSesData thd_data (thd);
		 audit (&thd_data);
	 }
	 THDVAR(thd, query_cache_table_list) = 0;
	 return res;
}
static unsigned int trampoline_send_result_to_client_size =0;

#if MYSQL_VERSION_ID > 50505
static bool audit_open_tables(THD *thd, TABLE_LIST **start, uint *counter, uint flags,
                Prelocking_strategy *prelocking_strategy)
{

     bool res;
     res = trampoline_open_tables (thd, start, counter, flags, prelocking_strategy);
     ThdSesData thd_data (thd);
     audit(&thd_data);
     return res;

}

static unsigned int trampoline_open_tables_size =0;
#else
static int audit_open_tables(THD *thd, TABLE_LIST **start, uint *counter, uint flags)
{
     bool res;
     res = trampoline_open_tables (thd, start, counter, flags);
     ThdSesData thd_data (thd);
     audit(&thd_data);
     return res;
}
static unsigned int trampoline_open_tables_size =0;
#endif


//called by log_slow_statement and general audit event caught by audit interface
static void audit_post_execute(THD * thd)
{
    //only audit non query events
    //query events are audited by mysql execute command
    if (Audit_formatter::thd_inst_command(thd) != COM_QUERY)
    {
        ThdSesData ThdData (thd);
        if (strcasestr (ThdData.getCmdName(), "show_fields")==NULL)
        {
            audit(&ThdData);
        }
    }
}



/*
 Plugin descriptor
 */
//in 5.6 we use the AUDIT plugin interface. In 5.1/5.5 we just use the general DAEMON plugin

#if MYSQL_VERSION_ID < 50600

static int plugin_type = MYSQL_DAEMON_PLUGIN;
static struct st_mysql_daemon audit_plugin =
{ MYSQL_DAEMON_INTERFACE_VERSION };

#else

static void audit_notify(THD *thd, unsigned int event_class,
        const void * event)
{
    if (MYSQL_AUDIT_GENERAL_CLASS == event_class)
    {
        const struct mysql_event_general *event_general =
                (const struct mysql_event_general *) event;
        if(MYSQL_AUDIT_GENERAL_STATUS == event_general->event_subclass)
        {
            audit_post_execute(thd);
        }
    }
    else if (MYSQL_AUDIT_CONNECTION_CLASS == event_class)
    {
        const struct mysql_event_connection *event_connection =
                (const struct mysql_event_connection *) event;
        //only audit for connect and change_user. disconnect is caught by general event
        if(event_connection->event_subclass != MYSQL_AUDIT_CONNECTION_DISCONNECT)
        {
            ThdSesData ThdData (thd);
            audit (&ThdData);
        }
    }
}

static int plugin_type = MYSQL_AUDIT_PLUGIN;
static struct st_mysql_audit audit_plugin=
{
  MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
  NULL,                                             /* release_thd function */
  audit_notify,                                /* notify function      */
  { (unsigned long) MYSQL_AUDIT_GENERAL_CLASSMASK |
                    MYSQL_AUDIT_CONNECTION_CLASSMASK } /* class mask           */
};

#endif


//some extern definitions which are not in include files
extern void log_slow_statement(THD *thd);
extern int mysql_execute_command(THD *thd);
#if MYSQL_VERSION_ID >= 50505
//in 5.5 builtins is named differently
#define mysqld_builtins mysql_mandatory_plugins
#endif
extern struct st_mysql_plugin *mysqld_builtins[];


void remove_hot_functions ()
{
    void * target_function = NULL;
#if MYSQL_VERSION_ID < 50600
	target_function = (void *) log_slow_statement;
	remove_hot_patch_function(target_function,
	(void*) trampoline_log_slow_statement, trampoline_log_slow_statement_size, true);
	trampoline_log_slow_statement_size=0;
#endif
#if MYSQL_VERSION_ID < 50505
	target_function = (void *) check_user;
	remove_hot_patch_function(target_function,
	(void*) trampoline_check_user, trampoline_check_user_size, true);
	trampoline_check_user_size=0;
#elif MYSQL_VERSION_ID < 50600
    target_function = (void *) acl_authenticate;
	remove_hot_patch_function(target_function,
	(void*) trampoline_acl_authenticate, trampoline_acl_authenticate_size, true);
	trampoline_acl_authenticate_size=0;
#endif	

#if MYSQL_VERSION_ID > 50505
	target_function = (void *)*(bool (*)(THD *thd, TABLE_LIST **start, uint *counter, uint flags,
                Prelocking_strategy *prelocking_strategy)) &open_tables;
	remove_hot_patch_function(target_function,
	(void*) trampoline_open_tables, trampoline_open_tables_size, true);
	trampoline_open_tables_size=0;
#else
	target_function = (void *)*(int (*)(THD *thd, TABLE_LIST **start, uint *counter, uint flags)) &open_tables;
	remove_hot_patch_function(target_function,
	(void*) trampoline_open_tables, trampoline_open_tables_size, true);
	trampoline_open_tables_size=0;
#endif

	int (Query_cache::*pf_send_result_to_client)(THD *,char *, uint) = &Query_cache::send_result_to_client;
	target_function = *(void **) &pf_send_result_to_client;
	remove_hot_patch_function(target_function,
	(void*) trampoline_send_result_to_client, trampoline_send_result_to_client_size, true);		
	trampoline_send_result_to_client_size=0;

	remove_hot_patch_function((void*) check_table_access,
		(void*) trampoline_check_table_access,
		trampoline_check_table_access_size, true);	
	trampoline_check_table_access_size=0;
	remove_hot_patch_function((void*)mysql_execute_command,
		(void*) trampoline_mysql_execute_command, 
		trampoline_mysql_execute_size, true);
	trampoline_mysql_execute_size=0;
}

int is_remove_patches (ThdSesData *pThdData)
	{	

		static bool called_once = false;
		const char *cmd = pThdData->getCmdName();
        const char *sUninstallPlugin = "uninstall_plugin";
		LEX *pLex = Audit_formatter::thd_lex(pThdData->getTHD());
		if (pThdData->getTHD() && pLex!=NULL && strncasecmp (cmd,sUninstallPlugin ,strlen (sUninstallPlugin))==0  ) 
		{
			LEX_STRING Lex_comment = *(LEX_STRING*)(((unsigned char *) pLex) + Audit_formatter::thd_offsets.lex_comment);
			if (strncasecmp(Lex_comment.str, "AUDIT", 5) == 0)
			{
				if (!uninstall_plugin_enable)
				{
		
                   my_message (ER_NOT_ALLOWED_COMMAND,"Uninstall AUDIT plugin disabled",MYF(0));
                   return 2;
				}
				Audit_handler::stop_all();
				remove_hot_functions ();
				if(!called_once)
				{
					called_once = true;
					my_message (WARN_PLUGIN_BUSY,"Uninstall AUDIT plugin must be called again to complete",MYF(0));
					return 2;
				}
				return 1;
			}
		}
	return 0;
}

/*
 * Over ride functions for hot patch + audit. We call our audit function
 * after the execute command so all tables are resolved.
 */
static int audit_mysql_execute_command(THD *thd) 
{
    bool firstTime = false;
     THDPRINTED *pThdPrintedList = GetThdPrintedList (thd);
     if (pThdPrintedList)
     {
        if (pThdPrintedList->cur_index < (MAX_NUM_QUEUE_ELEM -1)  )
        {
            pThdPrintedList->cur_index ++;
            pThdPrintedList->is_thd_printed_queue[pThdPrintedList->cur_index] =0;
        }
     }
     else
     {
         firstTime = true;
       pThdPrintedList = (THDPRINTED *) thd_alloc (thd, sizeof (THDPRINTED));
       if (pThdPrintedList) 
       {
           memset (pThdPrintedList, 0, sizeof (THDPRINTED));
           //pThdPrintedList->cur_index = 0;
           THDVAR(thd,is_thd_printed_list) = (ulong) pThdPrintedList;
       }
     }
    ThdSesData thd_data (thd);
    const char *cmd = thd_data.getCmdName();
    if (strcasestr (cmd,"alter") !=NULL ||  strcasestr (cmd,"drop") !=NULL || strcasestr (cmd, "create") !=NULL ||  strcasestr (cmd, "truncate") !=NULL ||  strcasestr (cmd, "rename") !=NULL)
    {
        audit(&thd_data);
    }
	int res;
	if(thd_killed(thd))
	{
	    res = 1;
	}
	else
	{
        switch (is_remove_patches(&thd_data))
        {
        case 1:
            //hot patch function were removed and we call the real execute (restored)
            res = mysql_execute_command(thd);
            break;
        case 2:
            //denied uninstall  plugin
            res = 1;
            break;
        default:
            //everything else
            res = trampoline_mysql_execute_command(thd);
        }
	}
    audit(&thd_data);
    if (pThdPrintedList && pThdPrintedList->cur_index >0)
    {
        pThdPrintedList->cur_index --;
    }
    if(firstTime)
    {
        THDVAR(thd,is_thd_printed_list) = 0;
    }
    return res;

}


#if MYSQL_VERSION_ID < 50600
static void audit_log_slow_statement(THD * thd)
{
    trampoline_log_slow_statement(thd);
    audit_post_execute(thd);
}
#endif

#if MYSQL_VERSION_ID < 50505
static int audit_check_user(THD *thd, enum enum_server_command command,
	       const char *passwd, uint passwd_len, const char *db,
	       bool check_count)
{
	int res = trampoline_check_user (thd, command, passwd, passwd_len, db, check_count);
	ThdSesData ThdData (thd);
    audit (&ThdData);

	return (res);
}
#elif MYSQL_VERSION_ID < 50600
//only for 5.5
//in 5.6: we use audit plugin event to get the login event
static bool audit_acl_authenticate(THD *thd, uint connect_errors, uint com_change_user_pkt_len)
{
    bool res = trampoline_acl_authenticate (thd, connect_errors, com_change_user_pkt_len);
    ThdSesData ThdData (thd);
    audit (&ThdData);
	return (res);
}
#endif

static bool parse_thd_offsets_string (char *poffsets_string)
{
		
    char  offset_str [2048] = {0};
	char *poffset_str = offset_str;
	strncpy (poffset_str,poffsets_string,2048);
	char * comma_delimiter = strchr (poffset_str,',');
	size_t i =0;
	OFFSET *pOffset;
	size_t len = strlen (poffset_str);

	for (size_t j=0;j<len;j++)
	{
		if (!((poffset_str[j] >= '0' && poffset_str[j] <='9') || poffset_str[j] == ' ' || poffset_str[j] == ','))
			return false;
	}
	while (comma_delimiter !=NULL)
	{
		*comma_delimiter = '\0';
		pOffset = (OFFSET*)&Audit_formatter::thd_offsets.query_id + i;
		if ((size_t)pOffset- (size_t)&Audit_formatter::thd_offsets < sizeof (Audit_formatter::thd_offsets))
		{
			sscanf (poffset_str, "%zu", pOffset);
		}
		else 
		{
			return false;
		}
		i++;
		poffset_str = comma_delimiter + 1;
		comma_delimiter = strchr (poffset_str,',');
	}
	if (poffset_str !=NULL)
	{
		pOffset = &Audit_formatter::thd_offsets.query_id + i;
		if ((size_t)pOffset- (size_t)&Audit_formatter::thd_offsets < sizeof (Audit_formatter::thd_offsets))
		{
			sscanf (poffset_str, "%zu", pOffset);
		}
		else
		{
			return false;
		}
	}
	return true;
}

static bool validate_offsets(const ThdOffsets * offset)
{
	//check that offsets are actually correct. We use a buff of memory as a dummy THD (32K is high enough)
	char buf[32*1024] = {0};
	THD * thd = (THD *)buf;
	//sanity check that offsets match
	
	//we set the thread id to a value using the offset and then check that the value matches what thd_get_thread_id returns	
	const my_thread_id thread_id_test_val = 123456;
	(*(my_thread_id *) (((char *) thd)+ offset->thread_id)) = thread_id_test_val;
	my_thread_id res= thd_get_thread_id(thd);
	if (res != thread_id_test_val)
	{
		sql_print_error(
			"%s Offsets: %s (%s) match thread validation check fails with value: %lu. Skipping offest.",
			log_prefix, offset->version, offset->md5digest, res);
		return false;
	}
	//extended validation via security_context method
	//can be disabled via: audit_validate_offsets_extended=OFF
	if(validate_offsets_extended_enable)
	{
	    const query_id_t query_id_test_val = 789;
	    (*(query_id_t *) (((char *) thd)+ offset->query_id)) = query_id_test_val;
	    Security_context * sctx = (Security_context *) (((unsigned char *) thd) + offset->main_security_ctx);
	    char user_test_val[] = "aud_tusr";
		if(!offset->sec_ctx_user) //use compiled header
		{
			sctx->user = user_test_val;
		}
	    else
		{
			(*(const char **) (((unsigned char *) sctx) + offset->sec_ctx_user)) = user_test_val;
		}
	    char buffer[2048] = {0};
	    thd_security_context(thd, buffer, 2048, 1000);
	    //verfiy our buffer contains query id
	    if(strstr(buffer, " 789") == NULL || strstr(buffer, user_test_val) == NULL)
	    {
	        sql_print_error(
                "%s Offsets: %s (%s) sec context validation check fails with value: %s. Skipping offest.",
                log_prefix, offset->version, offset->md5digest, buffer);
	        return false;
	    }
        sql_print_information(
            "%s extended offsets validate res: %s", log_prefix, buffer);
	}
	return true;
}

/**
 * Calculate md5 sum of a file.
 *
 * @file_name: file to calc md5 for
 * @digest_str: string to fill with digest result should be big enought to hold 32 chars
 *
 * @return true on success.
 */
static bool calc_file_md5(const char * file_name, char * digest_str)
{
    File fd;
    unsigned char digest[16] = {0};
    bool ret = false;
    if ((fd = my_open(file_name, O_RDONLY, MYF(MY_WME))) < 0)
    {
        sql_print_error("%s Failed file open: [%s], errno: %d.",
                            log_prefix, file_name, errno);
        return false;
    }

    my_MD5Context context;
    my_MD5Init(&context);
    const size_t buff_size = 16384;
    unsigned char file_buff[buff_size] = {0};

    ssize_t res;
    do
    {
        res = read(fd, file_buff, buff_size);
        if(res > 0)
        {
            my_MD5Update(&context, file_buff, res);
        }
    }
    while(res > 0);
    if(res == 0) //reached end of file
    {
        my_MD5Final(digest, &context);
        ret = true;
    }
    else
    {
        sql_print_error("%s Failed program read. res: %zd, errno: %d.",
                log_prefix, res, errno);
    }
    (void) my_close(fd, MYF(0));
    if(ret) //we got the digest
    {
        for (int j = 0; j < 16; j++)
        {
            sprintf(&(digest_str[j * 2]), "%02x", digest[j]);
        }
    }
    return ret;
}

/**
 * Setup the offsets needs to extract data from THD.
 *
 * return 0 on success otherwise 1
 */
static int setup_offsets()
{
    DBUG_ENTER("setup_offsets");
	sql_print_information ("%s setup_offsets audit_offsets: %s validate_checksum: %d offsets_by_version: %d",
	        log_prefix, offsets_string, validate_checksum_enable, offsets_by_version_enable);

	char digest_str [128] = {0};
	const ThdOffsets * offset;

    //setup digest_str to contain the md5sum in hex
	calc_file_md5(my_progname, digest_str);

    sql_print_information(
        "%s mysqld: %s (%s) ", log_prefix, my_progname, digest_str);

    //if present in my.cnf
    //[mysqld]
    //audit_validate_checksum=1
    // or if
    //audit_checksum=0f4d7e3b17eb36f17aafe4360993a769
    //if (validate_checksum_enable || (checksum_string != NULL && strlen(checksum_string) > 0))
    //{

    //if present the offset_string specified in my.cnf 
    //[mysqld]
    //audit_offsets=6200, 6264, 3672, 3944, 88, 2048

	if (offsets_string != NULL)
    {
        if (checksum_string != NULL && strlen(checksum_string) > 0)
        {
            if (strncasecmp(checksum_string, digest_str, 32))
            {
                sql_print_information(
                        "%s checksum check failed for %s, but found %s",
                        log_prefix, checksum_string, digest_str);
                DBUG_RETURN(1);
            }
        }
		if (parse_thd_offsets_string (offsets_string)) 
		{
			sql_print_information ("%s setup_offsets Audit_formatter::thd_offsets values: %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu", log_prefix,
				Audit_formatter::thd_offsets.query_id,
				Audit_formatter::thd_offsets.thread_id,
				Audit_formatter::thd_offsets.main_security_ctx, 
				Audit_formatter::thd_offsets.command,
				Audit_formatter::thd_offsets.lex,
				Audit_formatter::thd_offsets.lex_comment,
				Audit_formatter::thd_offsets.sec_ctx_user,
				Audit_formatter::thd_offsets.sec_ctx_host,
				Audit_formatter::thd_offsets.sec_ctx_ip,
				Audit_formatter::thd_offsets.sec_ctx_priv_user);

			if (!validate_offsets(&Audit_formatter::thd_offsets))
			{
				sql_print_error("%s Offsets set didn't pass validation. audit_offsets: %s .", log_prefix, offsets_string);
				DBUG_RETURN(1);
			}
		}
		else
		{
			sql_print_error("%s Failed parsing audit_offsets: %s", log_prefix, offsets_string);
			DBUG_RETURN(1);
		}
		sql_print_information ("%s Validation passed. Using offsets from audit_offsets: %s",log_prefix, offsets_string);
		DBUG_RETURN(0);
        //exit from function 
	}
	
    size_t arr_size = (sizeof(thd_offsets_arr) / sizeof(thd_offsets_arr[0]));
    //iterate and search for the first offset which matches our checksum
    if(validate_checksum_enable && strlen(digest_str) > 0)
    {
        for(size_t i=0; i < arr_size; i++)
        {
            offset = thd_offsets_arr + i;
            if (strlen(offset->md5digest) >0)
            {
                if (!strncasecmp(digest_str, offset->md5digest, 32))
                {
                    sql_print_information("%s Checksum verified. Using offsets from offset version: %s (%s)", log_prefix, offset->version, digest_str);
                    Audit_formatter::thd_offsets = *offset;
                    DBUG_RETURN(0);
                    //return
                }
            }
        }
    }
    if(offsets_by_version_enable)
    {
        bool server_is_ndb = strstr(server_version, "ndb") != NULL;
        for(size_t i=0; i < arr_size; i++)
        {
            offset = thd_offsets_arr + i;
            const char * version = offset->version;
            bool version_is_ndb = strstr(offset->version, "ndb") != NULL;
            const char * dash = strchr(version, '-');
            char version_stripped[16] = {0};
            if(dash) //we use the version string up to the '-'
            {
                size_t tocopy = dash - version;
                if(tocopy > 15) tocopy = 15; //sanity
                strncpy(version_stripped, version, tocopy);
                version = version_stripped;
            }
            if(strstr(server_version, version))
            {
                if(server_is_ndb == version_is_ndb)
                {
                    if (validate_offsets(offset))
                    {
                        sql_print_information("%s Using offsets from offset version: %s (%s)", log_prefix, offset->version, offset->md5digest);
                        Audit_formatter::thd_offsets = *offset;
                        DBUG_RETURN(0);
                    }
                    else
                    {
                        //try doing 24 byte decrement on THD offsets. Seen that on Ubuntu/Debian this is valid.
                        OFFSET dec = 24;
                        ThdOffsets decoffsets = *offset;
                        decoffsets.query_id -= dec;
                        decoffsets.thread_id -= dec;
                        decoffsets.main_security_ctx -= dec;
                        decoffsets.command -= dec;
                        if (validate_offsets(&decoffsets))
                        {
                            Audit_formatter::thd_offsets = decoffsets;
                            sql_print_information("%s Using decrement (%zu) offsets from offset version: %s (%s) values: %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu",
                                log_prefix, dec, offset->version, offset->md5digest,
                                Audit_formatter::thd_offsets.query_id,
                                Audit_formatter::thd_offsets.thread_id,
                                Audit_formatter::thd_offsets.main_security_ctx,
                                Audit_formatter::thd_offsets.command,
                                Audit_formatter::thd_offsets.lex,
                                Audit_formatter::thd_offsets.lex_comment,
								Audit_formatter::thd_offsets.sec_ctx_user,
								Audit_formatter::thd_offsets.sec_ctx_host,
								Audit_formatter::thd_offsets.sec_ctx_ip,
								Audit_formatter::thd_offsets.sec_ctx_priv_user);

                            DBUG_RETURN(0);
                        }
                    }
                }//ndb check
#if defined(__x86_64__) && MYSQL_VERSION_ID > 50505
                else if(server_is_ndb)
                {
                    //in 64bit 5.5 we've seen ndb has an offset of 32 on first 2 values
                    OFFSET inc = 32;
                    ThdOffsets incoffsets = *offset;
                    incoffsets.query_id += inc;
                    incoffsets.thread_id += inc;
                    if (validate_offsets(&incoffsets))
                    {
                        Audit_formatter::thd_offsets = incoffsets;
                        sql_print_information("%s Using increment (%zu) offsets from offset version: %s (%s) values: %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu",
                            log_prefix, inc, offset->version, offset->md5digest,
                            Audit_formatter::thd_offsets.query_id,
                            Audit_formatter::thd_offsets.thread_id,
                            Audit_formatter::thd_offsets.main_security_ctx,
                            Audit_formatter::thd_offsets.command,
                            Audit_formatter::thd_offsets.lex,
                            Audit_formatter::thd_offsets.lex_comment,
							Audit_formatter::thd_offsets.sec_ctx_user,
							Audit_formatter::thd_offsets.sec_ctx_host,
							Audit_formatter::thd_offsets.sec_ctx_ip,
							Audit_formatter::thd_offsets.sec_ctx_priv_user);
                        DBUG_RETURN(0);
                    }
                }
#endif
            }
        }
    }
	
    sql_print_information("%s Couldn't find proper THD offsets for: %s", log_prefix, server_version);
    DBUG_RETURN(1);
}


const char * retrieve_command (THD * thd, bool & is_sql_cmd)
{
    const char *cmd = NULL;
	is_sql_cmd = false;
    int command = Audit_formatter::thd_inst_command(thd);
    if (command < 0 || command > COM_END)
    {
        command = COM_END;
    }
    //check if from query cache. If so set to select and return
    if(THDVAR(thd, query_cache_table_list) != 0)
    {
        return "select";
    }
    const int sql_command = thd_sql_command(thd);
    if (sql_command >=0 && sql_command < MAX_COM_STATUS_VARS_RECORDS )
    {
		is_sql_cmd = true;
        cmd = com_status_vars_array[sql_command].name;
    }
    if(!cmd)
    {
        cmd = command_name[command].str;
    }
	const char * user = Audit_formatter::thd_inst_main_security_ctx_user(thd);
	const char * priv_user = Audit_formatter::thd_inst_main_security_ctx_priv_user(thd);
    if (strcmp (cmd, "Connect") ==0 && ((user && strcmp(user, "event_scheduler") != 0) && (priv_user == NULL || *priv_user == 0x0)))
    {
        cmd = "Failed Login";
    }
    return cmd;
}

static int set_com_status_vars_array ()
{
    DBUG_ENTER("set_com_status_vars_array");
    SHOW_VAR *com_status_vars;
    int sv_idx =0;
    while (strcmp (status_vars[sv_idx].name,"Com") !=0 && status_vars[sv_idx].name != NullS)
    {
        sv_idx ++;
    }
    if (strcmp (status_vars[sv_idx].name,"Com")==0)
    {
        com_status_vars = (SHOW_VAR*)status_vars[sv_idx].value;
        int status_vars_index =0;
        //we use "select" as 0 offset (SQLCOM_SELECT=0)

        while(strcmp(com_status_vars[status_vars_index].name,"select") !=0 && com_status_vars[status_vars_index].name != NullS)
        {
            status_vars_index ++;
        }
        if(strcmp(com_status_vars[status_vars_index].name,"select") !=0)
        {
            sql_print_error("%s Failed finding 'select' index in com_status_vars: [%p]. Plugin Init failed.",
                                   log_prefix, com_status_vars);
            DBUG_RETURN (1);
        }
        size_t initial_offset = (size_t) com_status_vars[status_vars_index].value;
        status_vars_index =0;
        while  (com_status_vars[status_vars_index].name != NullS)
        {
            int sql_command_idx = (com_status_vars[status_vars_index].value - (char*) (initial_offset)) / sizeof (ulong);
            if (sql_command_idx >=0 && sql_command_idx < MAX_COM_STATUS_VARS_RECORDS)
            {
                com_status_vars_array [sql_command_idx].name = com_status_vars[status_vars_index].name;
                com_status_vars_array [sql_command_idx].type = com_status_vars[status_vars_index].type;
                com_status_vars_array [sql_command_idx].value = com_status_vars[status_vars_index].value;
            }
            status_vars_index ++;
        }
        sql_print_information("%s Done initializing sql command names. status_vars_index: [%d], com_status_vars: [%p].",
                                               log_prefix, status_vars_index, com_status_vars);
    }
    else
    {
        sql_print_error("%s Failed looking up 'Com' entry in status_vars. Plugin Init failed.",
                       log_prefix);
        DBUG_RETURN (1);
    }
    DBUG_RETURN (0);
}
static int string_to_array(const void *save, void *array,
        int rows, int length)
{
    const char* save_string;
    save_string = *static_cast<const char* const *> (save);
    char* string_array;
    string_array = (char *) array;
    int r = 0;
    if (save_string != NULL)
    {
        int p = 0;
        for (int i = 0; save_string[i] != '\0'; i++)
        {
            if (save_string[i] == ' ' || save_string[i] == '\t'
                    || save_string[i] == ',')
            {
                if (p > 0)
                {
                    string_array[r * length + p] = '\0';
                    p = 0;
                    r++;
                    if (r == (rows - 1))
                    {
                        break;
                    }
                }
            }
            else
            {
                string_array[r * length + p] = tolower(save_string[i]);
                p++;
            }
        }
        if (p > 0)
        {
            string_array[r * length + p] = '\0';
            r++;
        }
        string_array[r * length + 0] = '\0';
    }
    return r;
}

/*
 * Utility function to setup record_objs_array.
 * Will use record_objs_string to setup.
 */
static void setup_record_objs_array()
{
	num_record_objs = string_to_array(&record_objs_string, record_objs_array, MAX_NUM_OBJECT_ELEM + 2, MAX_OBJECT_CHAR_NUMBERS);	
	if(num_record_objs > 0) //check if to record also the empty set of objects
	{ 
	  const char *objects[] = {"{}", NULL};
      record_empty_objs_set = check_array(objects, (const char *) record_objs_array, MAX_OBJECT_CHAR_NUMBERS);		 
	}
	else
	{
		record_empty_objs_set = true;
	}
	sql_print_information("%s Set num_record_objs: %d record objs: %s", log_prefix, num_record_objs, record_objs_string);
}

__attribute__ ((noinline)) static void trampoline_dummy_func_for_mem()
{
    TRAMPOLINE_NOP_DEF
}
//holds memory used for trampoline
static void * trampoline_mem = NULL;
//pointer to current free mem
static void * trampoline_mem_free = NULL;

/**
 * Utility method for hot patching 
 */
static int do_hot_patch(void ** trampoline_func_pp, unsigned int * trampoline_size,  
	void* target_function, void* audit_function,  const char * func_name)
{
	//16 byte align the pointer
	DATATYPE_ADDRESS addrs = (DATATYPE_ADDRESS)trampoline_mem_free + 15;
	*trampoline_func_pp = (void*)(addrs & ~0x0F);		
    //hot patch functions 
    
    int res = hot_patch_function(target_function, audit_function,
            *trampoline_func_pp, trampoline_size, true);
    if (res != 0)
    {
        //hot patch failed.
        sql_print_error("%s unable to hot patch %s (%p). res: %d.",
                log_prefix, func_name, target_function, res);
        return 1;
    }
    sql_print_information(
            "%s hot patch for: %s (%p) complete. Audit func: %p, Trampoline address: %p size: %u.",
            log_prefix, func_name, target_function, audit_function, *trampoline_func_pp, *trampoline_size);
	trampoline_mem_free = (void *)(((DATATYPE_ADDRESS)*trampoline_func_pp) + *trampoline_size + jump_size());
	return 0;
}

/*
 Initialize the plugin installation.

 SYNOPSIS
 audit_plugin_init()

 RETURN VALUE
 0                    success
 1                    failure
 */
 static int audit_plugin_init(void *p)
{

    DBUG_ENTER("audit_plugin_init");
	
	#ifdef __x86_64__
		const char * arch = "64bit";
	#else
		const char * arch = "32bit";
	#endif

	//See here: http://bugs.mysql.com/bug.php?id=56652
	int interface_ver = audit_plugin.interface_version ;
#if MYSQL_VERSION_ID < 50600
	interface_ver = interface_ver >> 8;
	//we ignore || (50600 <= interface_ver && interface_ver < 50604)) as GA was with 5.6.10
	need_free_memalloc_plugin_var = (interface_ver < 50519);
#endif
    sql_print_information(
            "%s starting up. Version: %s , Revision: %s (%s). AUDIT plugin interface version: %d (0x%x). MySQL Server version: %s.",
            log_prefix, MYSQL_AUDIT_PLUGIN_VERSION,
            MYSQL_AUDIT_PLUGIN_REVISION, arch, interface_ver, interface_ver,
            server_version);
    //setup our offsets.

    if(setup_offsets() != 0)
    {
        DBUG_RETURN(1);
    }
  if (delay_cmds_string != NULL) {
    num_delay_cmds = string_to_array(&delay_cmds_string, delay_cmds_array, SQLCOM_END + 2, MAX_COMMAND_CHAR_NUMBERS);
    sql_print_information("%s Set num_delay_cmds: %d", log_prefix, num_delay_cmds);
  }
  if (record_cmds_string != NULL) {
    num_record_cmds = string_to_array(&record_cmds_string, record_cmds_array, SQLCOM_END + 2, MAX_COMMAND_CHAR_NUMBERS);
    sql_print_information("%s Set num_record_cmds: %d", log_prefix, num_record_cmds);
  }
 if (whitelist_users_string != NULL) {
    num_whitelist_users = string_to_array(&whitelist_users_string, whitelist_users_array, MAX_NUM_USER_ELEM + 2, MAX_USER_CHAR_NUMBERS);
    sql_print_information("%s Set num_whitelist_users: %d", log_prefix, num_whitelist_users);
  }


  if (record_objs_string != NULL) {
	setup_record_objs_array();    
  }
   
    //setup audit handlers (initially disabled)
    int res = json_file_handler.init(&json_formatter);
    if (res != 0)
    {
        sql_print_error(
                "%s unable to init json file handler. res: %d. Aborting.",
                log_prefix, res);
        DBUG_RETURN(1);
    }
    res = json_socket_handler.init(&json_formatter);
    if (res != 0)
    {
        sql_print_error(
                "%s unable to init json socket handler. res: %d. Aborting.",
                log_prefix, res);
        DBUG_RETURN(1);
    }
    //enable according to what we have in *file_handler_enable (this is set accordingly by sysvar functionality)
    json_file_handler.set_enable(json_file_handler_enable);
    json_socket_handler.set_enable(json_socket_handler_enable);
    Audit_handler::m_audit_handler_list[Audit_handler::JSON_FILE_HANDLER]
            = &json_file_handler;
    Audit_handler::m_audit_handler_list[Audit_handler::JSON_SOCKET_HANDLER]
            = &json_socket_handler;
	
	//align our trampoline mem on its own page
	const unsigned long page_size = GETPAGESIZE();
	const unsigned long std_page_size = 4096;
	if(page_size <= std_page_size)
	{
		//use static executable memory we alocated via trampoline_dummy_func_for_mem
		DATATYPE_ADDRESS addrs = (DATATYPE_ADDRESS)trampoline_dummy_func_for_mem + (page_size - 1);	
		trampoline_mem = (void*)(addrs & ~(page_size - 1));
		sql_print_information(
				"%s mem func addr: %p mem start addr: %p page size: %ld",
				log_prefix, trampoline_dummy_func_for_mem, trampoline_mem, page_size);
	}
	else //big pages for some reason. allocate mem using mmap
	{	
		trampoline_mem = mmap(NULL, page_size, PROT_READ|PROT_EXEC,  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if(MAP_FAILED == trampoline_mem)
		{
			sql_print_error("%s unable to mmap memory size: %lu, errno: %d. Aborting.",
					log_prefix, page_size, errno);
			DBUG_RETURN(1);
		}
		else
		{
			sql_print_information(
				"%s mem via mmap: %p page size: %ld", log_prefix, trampoline_mem, page_size);
		}
	}
	trampoline_mem_free = trampoline_mem;
	//hot patch stuff
	void * target_function = NULL;
#if MYSQL_VERSION_ID < 50600
	if(do_hot_patch((void **)&trampoline_log_slow_statement, &trampoline_log_slow_statement_size,  
		(void *)log_slow_statement, (void *)audit_log_slow_statement,  "log_slow_statement"))
	{
		sql_print_error("%s Failed hot patch. Continuing as non-critical.",
                log_prefix);		
				
	}
#endif
	
	if(do_hot_patch((void **)&trampoline_mysql_execute_command, &trampoline_mysql_execute_size,  
		(void *)mysql_execute_command, (void *)audit_mysql_execute_command,  "mysql_execute_command"))
	{
		DBUG_RETURN(1);
	}
	    
 
#if MYSQL_VERSION_ID < 50505				
	if(do_hot_patch((void **)&trampoline_check_user, &trampoline_check_user_size,  
		(void *)check_user, (void *)audit_check_user,  "check_user"))
	{
		DBUG_RETURN(1);
	}	
#elif MYSQL_VERSION_ID < 50600
	if(do_hot_patch((void **)&trampoline_acl_authenticate, &trampoline_acl_authenticate_size,  
		(void *)acl_authenticate, (void *)audit_acl_authenticate,  "acl_authenticate"))
	{
		DBUG_RETURN(1);
	}
#endif
	int (Query_cache::*pf_send_result_to_client)(THD *,char *, uint) = &Query_cache::send_result_to_client;	
	target_function = *(void **)  &pf_send_result_to_client;
	if(do_hot_patch((void **)&trampoline_send_result_to_client, &trampoline_send_result_to_client_size,  
		(void *)target_function, (void *)audit_send_result_to_client,  "send_result_to_client"))
	{
		DBUG_RETURN(1);
	}
	
    if(do_hot_patch((void **)&trampoline_check_table_access, &trampoline_check_table_access_size,  
		(void *)check_table_access, (void *)audit_check_table_access,  "check_table_access"))
	{
		DBUG_RETURN(1);
	}
		
#if MYSQL_VERSION_ID > 50505				
	target_function = (void *)*(bool (*)(THD *thd, TABLE_LIST **start, uint *counter, uint flags,
                Prelocking_strategy *prelocking_strategy)) &open_tables;
	if(do_hot_patch((void **)&trampoline_open_tables, &trampoline_open_tables_size,  
		(void *)target_function, (void *)audit_open_tables,  "open_tables"))
	{
		DBUG_RETURN(1);
	}		    
#else
    target_function = (void *)*(int (*)(THD *thd, TABLE_LIST **start, uint *counter, uint flags)) &open_tables;
	if(do_hot_patch((void **)&trampoline_open_tables, &trampoline_open_tables_size,  
		(void *)target_function, (void *)audit_open_tables,  "open_tables"))
	{
		DBUG_RETURN(1);
	}    
#endif
    if (set_com_status_vars_array () !=0)
    {
        DBUG_RETURN(1);
    }
	sql_print_information("%s Init completed successfully.", log_prefix);
    DBUG_RETURN(0);
}

/*
 plugin deinstallation.

 SYNOPSIS
 audit_plugin_deinit()
 Does nothing.

 RETURN VALUE
 0                    success
 1                    failure (cannot happen)

 */

static int audit_plugin_deinit(void *p)
{	
    DBUG_ENTER("audit_plugin_deinit");	
	sql_print_information("%s deinit", log_prefix);
	remove_hot_functions();
	DBUG_RETURN(0);    
}

/*
 Plugin status variables for SHOW STATUS
 */

static struct st_mysql_show_var audit_status[] =
{
{ "Audit_version",
        (char *) MYSQL_AUDIT_PLUGIN_VERSION "-" MYSQL_AUDIT_PLUGIN_REVISION,
        SHOW_CHAR },
{ "Audit_protocol_version",
		(char *) "1.0",
		SHOW_CHAR },
//{"called",     (char *)&number_of_calls, SHOW_LONG},
        { 0, 0, (enum_mysql_show_type) 0 } };



static void json_log_file_enable(THD *thd, struct st_mysql_sys_var *var,
        void *tgt, const void *save)
{
    json_file_handler_enable = *(my_bool *) save ? TRUE : FALSE;
    if(json_file_handler.is_init())
    {
        json_file_handler.set_enable(json_file_handler_enable);
    }
}

static void json_log_file_flush(THD *thd, struct st_mysql_sys_var *var,
        void *tgt, const void *save)
{
	//always set to false. as we just flush if set to true and leave at 0
    json_file_handler_flush = FALSE;
	my_bool val = *(my_bool *) save ? TRUE : FALSE;
    if(val && json_file_handler.is_init())
    {
        json_file_handler.flush();
    }
}




static void json_log_socket_enable(THD *thd, struct st_mysql_sys_var *var,
        void *tgt, const void *save)
{
    json_socket_handler_enable = *(my_bool *) save ? TRUE : FALSE;
    if(json_socket_handler.is_init())
    {
        json_socket_handler.set_enable(json_socket_handler_enable);
    }
}

static void delay_cmds_string_update(THD *thd,
        struct st_mysql_sys_var *var, void *tgt,
        const void *save)
{
    num_delay_cmds = string_to_array(save, delay_cmds_array, SQLCOM_END + 2, MAX_COMMAND_CHAR_NUMBERS);

    if (need_free_memalloc_plugin_var)
    {
        x_free(delay_cmds_string);
        delay_cmds_string = my_strdup(*static_cast<char*const*>(save), MYF(MY_WME));
    }
    else
    {
        delay_cmds_string = *static_cast<char* const *> (save);
    }

    sql_print_information("%s Set num_delay_cmds: %d, delay cmds: %s", log_prefix, num_delay_cmds, delay_cmds_string);
}

static void record_cmds_string_update(THD *thd,
        struct st_mysql_sys_var *var, void *tgt,
        const void *save)
{
    num_record_cmds = string_to_array(save, record_cmds_array, SQLCOM_END + 2, MAX_COMMAND_CHAR_NUMBERS);

    if (need_free_memalloc_plugin_var)
    {
        x_free(record_cmds_string);
        record_cmds_string = my_strdup(*static_cast<char*const*>(save), MYF(MY_WME));
    }
    else
    {
        record_cmds_string = *static_cast<char* const *> (save);
    }

    sql_print_information("%s Set num_record_cmds: %d record cmds: %s", log_prefix, num_record_cmds, record_cmds_string);
}
static void whitelist_users_string_update(THD *thd,
        struct st_mysql_sys_var *var, void *tgt,
        const void *save)
{
    num_whitelist_users = string_to_array(save, whitelist_users_array, MAX_NUM_USER_ELEM + 2, MAX_USER_CHAR_NUMBERS);
    if (need_free_memalloc_plugin_var)
    {
        x_free(whitelist_users_string);
        whitelist_users_string = my_strdup(*static_cast<char*const*>(save), MYF(MY_WME));
    }
    else
    {
        whitelist_users_string = *static_cast<char* const *> (save);
    }	
    sql_print_information("%s Set num_whitelist_users: %d whitelist users: %s", log_prefix, num_whitelist_users, whitelist_users_string);
}



static void record_objs_string_update(THD *thd,
        struct st_mysql_sys_var *var, void *tgt,
        const void *save)
{
    if (need_free_memalloc_plugin_var)
    {
        x_free(record_objs_string);
        record_objs_string = my_strdup(*static_cast<char*const*>(save), MYF(MY_WME));
    }
    else
    {
        record_objs_string = *static_cast<char* const *> (save);
    }

    setup_record_objs_array();
}

//setup sysvars which update directly the relevant plugins


static MYSQL_SYSVAR_STR(json_log_file, json_file_handler.m_filename,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
        "AUDIT plugin json log file name",
        NULL, NULL, "mysql-audit.json");

static MYSQL_SYSVAR_UINT(json_file_sync, json_file_handler.m_sync_period,
        PLUGIN_VAR_RQCMDARG,
        "AUDIT plugin json log file sync period. If the value of this variable is greater than 0, audit log will sync to disk after every audit_json_file_sync writes.",
        NULL, NULL, 0, 0, UINT_MAX32, 0);

static MYSQL_SYSVAR_BOOL(json_file, json_file_handler_enable,
			 PLUGIN_VAR_RQCMDARG,
        "AUDIT plugin json log file Enable|Disable", NULL, json_log_file_enable, 0);
		
static MYSQL_SYSVAR_BOOL(json_file_flush, json_file_handler_flush,
			 PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_NOCMDOPT,
        "AUDIT plugin json log file flush. Set to ON to perform a flush of the log.", NULL, json_log_file_flush, 0);


static MYSQL_SYSVAR_STR(json_socket_name, json_socket_handler.m_sockname,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
        "AUDIT plugin json log unix socket name",
        NULL, NULL, "/tmp/mysql-audit.json.sock");

static MYSQL_SYSVAR_STR(offsets, offsets_string,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY  | PLUGIN_VAR_MEMALLOC,
        "AUDIT plugin offsets. Comma separated list of offsets to use for extracting data",
        NULL, NULL, NULL);

static MYSQL_SYSVAR_STR(checksum, checksum_string,
			PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY  | PLUGIN_VAR_MEMALLOC,
			"AUDIT plugin checksum. Checksum for mysqld corresponding to offsets",
			NULL, NULL, "");
static MYSQL_SYSVAR_BOOL(uninstall_plugin, uninstall_plugin_enable,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY ,
        "AUDIT uninstall plugin Enable|Disable. Default disabled. If disabled attempts to uninstall the AUDIT plugin via the sql UNINSTALL command will fail.", NULL, NULL, 0);


static MYSQL_SYSVAR_BOOL(offsets_by_version, offsets_by_version_enable,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY ,
        "AUDIT plugin search offsets by version. If checksum validation doesn't pass will attempt to load and validate offsets according to version. Enable|Disable", NULL, NULL, 1);

static MYSQL_SYSVAR_BOOL(validate_checksum, validate_checksum_enable,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY ,
        "AUDIT plugin binary checksum validation Enable|Disable", NULL, NULL, 1);


static MYSQL_SYSVAR_BOOL(validate_offsets_extended, validate_offsets_extended_enable,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY ,
        "AUDIT plugin offset extended validation Enable|Disable", NULL, NULL, 1);

static MYSQL_SYSVAR_BOOL(json_socket, json_socket_handler_enable,
			 PLUGIN_VAR_RQCMDARG,
        "AUDIT plugin json log unix socket Enable|Disable", NULL, json_log_socket_enable, 0);

static MYSQL_SYSVAR_INT(delay_ms, delay_ms_val,
        PLUGIN_VAR_RQCMDARG,
        "AUDIT plugin delay in miliseconds. Delay amount injection. If 0 or negative then delay is disabled.",
        NULL, NULL, 0, 0, INT_MAX32, 0);

static MYSQL_SYSVAR_STR(delay_cmds, delay_cmds_string,
        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
        "AUDIT plugin delay commands to match against comma separated. If empty then delay is disabled.",
			NULL, delay_cmds_string_update, NULL);
static MYSQL_SYSVAR_STR(record_cmds, record_cmds_string,
			PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
			"AUDIT plugin commands to record, comma separated",
			NULL, record_cmds_string_update, NULL);
static MYSQL_SYSVAR_STR(whitelist_users, whitelist_users_string,
			PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
			"AUDIT plugin whitelisted users whose queries are not to recorded, comma separated",
			NULL, whitelist_users_string_update, NULL);

static MYSQL_SYSVAR_STR(record_objs, record_objs_string,
			PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
			"AUDIT plugin objects to record, comma separated",
			NULL, record_objs_string_update, NULL);

/*
 * Plugin system vars
 */
static struct st_mysql_sys_var* audit_system_variables[] =
{
        MYSQL_SYSVAR(json_log_file),
        MYSQL_SYSVAR(json_file_sync),
        MYSQL_SYSVAR(json_file),
		MYSQL_SYSVAR(json_file_flush),
		MYSQL_SYSVAR(uninstall_plugin),
		MYSQL_SYSVAR(validate_checksum),
		MYSQL_SYSVAR(offsets_by_version),
		MYSQL_SYSVAR(validate_offsets_extended),
		MYSQL_SYSVAR(json_socket_name),
		MYSQL_SYSVAR(offsets),
        MYSQL_SYSVAR(json_socket),
		MYSQL_SYSVAR(query_cache_table_list),
        MYSQL_SYSVAR(is_thd_printed_list),
        MYSQL_SYSVAR(delay_ms),
        MYSQL_SYSVAR(delay_cmds),
    MYSQL_SYSVAR(record_cmds),
    MYSQL_SYSVAR(whitelist_users),
    MYSQL_SYSVAR(record_objs),
    MYSQL_SYSVAR(checksum),
        NULL };

//declare our plugin
mysql_declare_plugin(audit_plugin)
{
    plugin_type,
    &audit_plugin,
    "AUDIT",
    "McAfee Inc",
    "AUDIT plugin, creates a file mysql-audit.log to log activity",
    PLUGIN_LICENSE_GPL,
    audit_plugin_init, /* Plugin Init */
    audit_plugin_deinit, /* Plugin Deinit */
    0x0100 /* 1.0 */,
    audit_status, /* status variables                */
    audit_system_variables, /* system variables                */
    NULL /* config options                  */
}
mysql_declare_plugin_end;

#if MYSQL_VERSION_ID < 50505
/**
 * DLL constructor method.
 * We set here the audit plugin version to the same as the first built in plugin.
 * This is so we can have a single lib for all versions (needed in 5.1)
 */
extern "C" void __attribute__ ((constructor)) audit_plugin_so_init(void)
{
    if (mysqld_builtins && mysqld_builtins[0])
    {
        audit_plugin.interface_version = *(int *) mysqld_builtins[0]->info;
        sql_print_information("%s Set interface version to: %d (%d)",
                log_prefix, audit_plugin.interface_version,
                audit_plugin.interface_version >> 8);
    }
    else
    {
        sql_print_error(
                "%s mysqld_builtins are null. Plugin will not load unless the mysql version is: %d. \n",
                log_prefix, audit_plugin.interface_version >> 8);
    }
}
#elif MYSQL_VERSION_ID < 50600
extern struct st_mysql_plugin *mysql_mandatory_plugins[];
extern "C"  void __attribute__ ((constructor)) audit_plugin_so_init(void)
{

	
	audit_plugin.interface_version = *(int *) mysql_mandatory_plugins[0]->info;
    sql_print_information("%s Set interface version to: %d (%d)",
              log_prefix, audit_plugin.interface_version,
               audit_plugin.interface_version >> 8);

}
#else
//interface version for 5.6 changed in 5.6.14 
extern "C"  void __attribute__ ((constructor)) audit_plugin_so_init(void)
{
	const char * ver_5_6_13 = "5.6.13";
	if(strncmp(server_version, ver_5_6_13, strlen(ver_5_6_13)) <= 0)
	{
		audit_plugin.interface_version = 0x0300;
	}
	else
	{
		audit_plugin.interface_version = 0x0301;
	}
}
#endif

/*
 Pure virtual handler. Needed when running in mysql compiled with a newer version of gcc.
 Versions of mysql for RH 6 and Percona this function is defined local in mysqld. 
 So we define our own implementation.
*/
extern "C" int __cxa_pure_virtual (void)
{
	sql_print_error(
		"%s __cxa_pure_virtual called. Fatal condition. ",
		log_prefix);
	return 0;
}
