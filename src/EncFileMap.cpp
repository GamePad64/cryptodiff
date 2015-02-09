/*
 * EncFileMap.cpp
 *
 *  Created on: 04 февр. 2015 г.
 *      Author: gamepad
 */

#include "EncFileMap.h"
#include "EncFileMap.pb.h"

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
	EncFileMap_s serialized_map;
	serialized_map.set_maxblocksize(maxblocksize);
	serialized_map.set_minblocksize(minblocksize);
	for(auto block : offset_blocks){
		auto new_block = serialized_map.add_blocks();
		new_block->set_encrypted_hash(block.second->encrypted_hash.data(), block.second->encrypted_hash.size());
		new_block->set_blocksize(block.second->blocksize);
		new_block->set_iv(block.second->iv.data(), block.second->iv.size());
		new_block->set_encrypted_hashes(block.second->encrypted_hashes_part.data(), block.second->encrypted_hashes_part.size());
	}
	serialized_map.SerializeToOstream(&lvfile);
}

void EncFileMap::print_debug() const {
	int i = 0;
	for(auto chunk : offset_blocks){
		std::cout << "#: " << ++i << " L: " << chunk.second->blocksize << std::endl;
		std::cout << "SHA3(Enc): " << to_hex(chunk.second->encrypted_hash.data()) << std::endl;
		std::cout << "IV: " << to_hex(chunk.second->iv.data()) << std::endl;

		std::cout << "AES(Hashes(Block)): " << to_hex(chunk.second->encrypted_hashes_part.data()) << std::endl << std::endl;
		//std::cout << "Rsync: " << to_hex(chunk.second->encrypted.weak_hash) << std::endl;
		//std::cout << "SHA-3: " << to_hex(chunk.second->encrypted.strong_hash.data()) << std::endl;
	}
}
