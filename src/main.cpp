/* Copyright (C) 2014-2015 Alexander Shishenko <GamePad64@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <botan/symkey.h>
#include <botan/botan.h>
#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/iostreams/stream.hpp>
#include <iostream>
#include <fstream>

#include "FileMap.h"

using namespace librevault;

int main(int argc, char** argv){
	Botan::LibraryInitializer init("thread_safe=true");

	if(argc < 2){return 1;}

	if(strcmp(argv[1], "create") == 0){
		std::ifstream datafile(argv[2]);
		std::ofstream mapfile(argv[3]);

		FileMap filemap(Botan::SymmetricKey(reinterpret_cast<uint8_t*>(argv[4]), AES_KEYSIZE));
		filemap.create(datafile);
		filemap.to_file(mapfile);
	}else if(strcmp(argv[1], "read") == 0){
		std::ifstream mapfile(argv[2]);

		std::unique_ptr<EncFileMap> filemap;
		if(argc == 4){
			filemap = std::unique_ptr<EncFileMap>(new FileMap(Botan::SymmetricKey(reinterpret_cast<uint8_t*>(argv[3]), AES_KEYSIZE)));
		}else{
			filemap = std::unique_ptr<EncFileMap>(new EncFileMap());
		}

		filemap->from_file(mapfile);
		filemap->print_debug();
	}else if(strcmp(argv[1], "update") == 0){	// also known as rechunk
		std::ifstream datafile(argv[2]);
		std::ifstream mapfile_old(argv[3]);
		std::ofstream mapfile_new(argv[4]);

		FileMap filemap_old(Botan::secure_vector<uint8_t>(argv[5], argv[5]+AES_KEYSIZE));
		filemap_old.from_file(mapfile_old);
		FileMap filemap_new = filemap_old.update(datafile);
		filemap_new.to_file(mapfile_new);
	}
}
