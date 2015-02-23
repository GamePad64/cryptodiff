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
#include "EncFileMap.h"
#include <boost/range/adaptor/map.hpp>

namespace cryptodiff {
namespace internals {

EncFileMap::EncFileMap() {}
EncFileMap::~EncFileMap() {}

std::list<std::shared_ptr<const Block>> EncFileMap::delta(const EncFileMap& old_filemap){
	auto strong_hash_less = [](const decltype(offset_blocks | boost::adaptors::map_values)::value_type &block1, const decltype(offset_blocks | boost::adaptors::map_values)::value_type &block2){
		return block1->encrypted_hash < block2->encrypted_hash;
	};

	std::list<std::shared_ptr<const Block>> missing_blocks;
	std::set_difference(
			(offset_blocks | boost::adaptors::map_values).begin(), (offset_blocks | boost::adaptors::map_values).end(),
			(old_filemap.offset_blocks | boost::adaptors::map_values).begin(), (old_filemap.offset_blocks | boost::adaptors::map_values).end(),
			std::back_inserter(missing_blocks), strong_hash_less);
	return missing_blocks;
}

void EncFileMap::from_protobuf(const EncFileMap_s& filemap_s) {
	size = 0;
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

EncFileMap_s EncFileMap::to_protobuf() const {
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
	return serialized_map;
}

void EncFileMap::from_string(const std::string& serialized_str) {
	EncFileMap_s filemap_s; filemap_s.ParseFromString(serialized_str);
	from_protobuf(filemap_s);
}

std::string EncFileMap::to_string() const {
	std::string filemap_str;
	to_protobuf().SerializeToString(&filemap_str);
	return filemap_str;
}

void EncFileMap::from_file(std::istream& lvfile){
	EncFileMap_s filemap_s; filemap_s.ParseFromIstream(&lvfile);
	from_protobuf(filemap_s);
}

void EncFileMap::to_file(std::ostream& lvfile){
	to_protobuf().SerializeToOstream(&lvfile);
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

} /* namespace internals */
} /* namespace librevault */