/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "LVMap.h"
#include <botan/botan.h>
#include <iostream>
#include <fstream>

int main(int argc, char** argv){
	Botan::LibraryInitializer init("thread_safe=true");

	if(argc < 2){return 1;}

	if(strcmp(argv[1], "create") == 0){
		std::ifstream datafile(argv[2]);
		std::ofstream lvfile(argv[3]);

		LVMap lvmap(Botan::secure_vector<uint8_t>(argv[4], argv[4]+AES_KEYSIZE));
		lvmap.create(datafile);
		lvmap.to_file(lvfile);
	}else if(strcmp(argv[1], "read") == 0){
		std::ifstream lvfile(argv[2]);

		LVMap lvmap;
		lvmap.from_file(lvfile);
		lvmap.print_debug();
	}else if(strcmp(argv[1], "update") == 0){	// also known as rechunk
		std::ifstream datafile(argv[2]);
		std::ifstream lvfile_old(argv[3]);
		std::ofstream lvfile_new(argv[4]);

		LVMap lvmap_old(Botan::secure_vector<uint8_t>(argv[5], argv[5]+AES_KEYSIZE));
		lvmap_old.from_file(lvfile_old);
		LVMap lvmap_new = lvmap_old.update(datafile);
		lvmap_new.to_file(lvfile_new);
	}
}
