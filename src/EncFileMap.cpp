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
	EncFileMap_s filemap_s; filemap_s.ParseFromIstream(&lvfile);

	maxblocksize = filemap_s.maxblocksize();
	minblocksize = filemap_s.minblocksize();

	for(auto block_s : filemap_s.blocks()){
		auto new_block = std::make_shared<Block>();
		std::copy(block_s.encrypted_hash().begin(), block_s.encrypted_hash().end(), new_block->encrypted_hash.begin());
		new_block->blocksize = block_s.blocksize();
		std::copy(block_s.iv().begin(), block_s.iv().end(), new_block->iv.begin());
		std::copy(block_s.encrypted_hashes().begin(), block_s.encrypted_hashes().end(), new_block->encrypted_hashes_part.begin());

		offset_blocks.insert(make_pair(size, new_block));
		size += block_s.blocksize();
	}
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
	for(auto block : offset_blocks){
		print_debug_block(*(block.second), ++i);
	}
}

void EncFileMap::print_debug_block(const Block& block, int count) const {
	std::cout << "#: " << count << " L: " << block.blocksize << std::endl;
	std::cout << "SHA3(Enc): " << to_hex(block.encrypted_hash.data(), SHASH_LENGTH) << std::endl;
	std::cout << "IV: " << to_hex(block.iv.data(), AES_BLOCKSIZE) << std::endl;

	std::cout << "AES(Hashes(Block)): " << to_hex(block.encrypted_hashes_part.data(), block.encrypted_hashes_part.size()) << std::endl << std::endl;
}
