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
#include "src/cryptodiff.h"

#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/iostreams/stream.hpp>
#include <iostream>
#include <fstream>


using namespace cryptodiff;

int main(int argc, char** argv){
	if(argc < 2){return 1;}

	if(strcmp(argv[1], "create") == 0){
		std::ifstream datafile(argv[2]);
		std::ofstream mapfile(argv[3]);

		std::array<uint8_t, 32> key;
		std::copy((uint8_t*)argv[4], (uint8_t*)argv[4]+32, key.data());
		FileMap filemap(key);
		filemap.create(datafile);
		filemap.to_file(mapfile);
	}else if(strcmp(argv[1], "read") == 0){
		std::ifstream mapfile(argv[2]);

		std::unique_ptr<EncFileMap> filemap;
		if(argc == 4){
			std::array<uint8_t, 32> key;
			std::copy((uint8_t*)argv[3], (uint8_t*)argv[3]+32, key.data());
			filemap = std::unique_ptr<EncFileMap>(new FileMap(key));
		}else{
			filemap = std::unique_ptr<EncFileMap>(new EncFileMap());
		}

		filemap->from_file(mapfile);
		filemap->print_debug();
	}else if(strcmp(argv[1], "update") == 0){	// also known as rechunk
		std::ifstream datafile(argv[2]);
		std::ifstream mapfile_old(argv[3]);
		std::ofstream mapfile_new(argv[4]);

		std::array<uint8_t, 32> key;
		std::copy((uint8_t*)argv[4], (uint8_t*)argv[4]+32, key.data());

		FileMap filemap_old(key);
		filemap_old.from_file(mapfile_old);
		FileMap filemap_new = filemap_old.update(datafile);
		filemap_new.to_file(mapfile_new);
	}else if(strcmp(argv[1], "delta") == 0){	// also known as rechunk
		std::ifstream mapfile_old(argv[2]);
		std::ifstream mapfile_new(argv[3]);

		EncFileMap filemap_old;
		EncFileMap filemap_new;
		filemap_old.from_file(mapfile_old);
		filemap_new.from_file(mapfile_new);

		auto missing_blocks = filemap_new.delta(filemap_old);
		auto i = 0;
		for(auto block : missing_blocks){
			filemap_new.print_debug_block(block, ++i);
		}
	}
}
