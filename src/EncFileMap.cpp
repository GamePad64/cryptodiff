/*
 * EncFileMap.cpp
 *
 *  Created on: 04 февр. 2015 г.
 *      Author: gamepad
 */

#include "EncFileMap.h"

EncFileMap::EncFileMap() {
	// TODO Auto-generated constructor stub

}

EncFileMap::~EncFileMap() {
	// TODO Auto-generated destructor stub
}

void EncFileMap::from_file(std::istream& lvfile){
	size = 0;
	do {
		std::shared_ptr<Block> block = std::make_shared<Block>();
		lvfile.read(reinterpret_cast<char*>(block.get()), sizeof(Block));

		if(lvfile.gcount() == sizeof(Block)){
			//hashed_blocks.insert(std::make_pair(block->encrypted.weak_hash, block));
			offset_blocks.insert(std::make_pair(size, block));
			size += block->blocksize;
		}
	} while(lvfile.good());
}

void EncFileMap::to_file(std::ostream& lvfile){
	for(auto chunk : offset_blocks){
		lvfile.write(reinterpret_cast<char*>(chunk.second.get()), sizeof(Block));
	}
}

void EncFileMap::print_debug() const {
	int i = 0;
	for(auto chunk : offset_blocks){
		std::cout << "#: " << ++i << " L: " << chunk.second->blocksize << std::endl;
		std::cout << "SHA3(Enc): " << to_hex(chunk.second->encrypted_hash.data()) << std::endl;
		std::cout << "IV: " << to_hex(chunk.second->iv.data()) << std::endl;

		std::cout << "AES(Hashes(Block)): " << to_hex(chunk.second->encrypted_data.data()) << std::endl << std::endl;
		//std::cout << "Rsync: " << to_hex(chunk.second->encrypted.weak_hash) << std::endl;
		//std::cout << "SHA-3: " << to_hex(chunk.second->encrypted.strong_hash.data()) << std::endl;
	}
}
