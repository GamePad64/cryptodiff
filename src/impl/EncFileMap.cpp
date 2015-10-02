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

namespace cryptodiff {
namespace internals {

void Block::encrypt_hashes(const blob& key){
	struct Hashes {
		uint32_t weak_hash;
		std::array<uint8_t, 28> strong_hash;
	} temp_hashes;
	temp_hashes.weak_hash = boost::endian::native_to_big(weak_hash);
	std::copy(strong_hash.begin(), strong_hash.end(), temp_hashes.strong_hash.end());

	auto encrypted_vector = blob((uint8_t*)&temp_hashes, (uint8_t*)&temp_hashes+sizeof(Hashes)) |
			crypto::AES_CBC(key, iv, false);

	std::move(encrypted_vector.begin(), encrypted_vector.end(), encrypted_hashes_part.begin());
}

void Block::decrypt_hashes(const blob& key){
	auto decrypted_vector = crypto::AES_CBC(key, iv, false).from(
					blob(encrypted_hashes_part.begin(), encrypted_hashes_part.end())
					);

	struct Hashes {
		uint32_t weak_hash;
		std::array<uint8_t, 28> strong_hash;
	} temp_hashes;
	std::move(decrypted_vector.begin(), decrypted_vector.end(), (uint8_t*)&temp_hashes);

	weak_hash = boost::endian::big_to_native(temp_hashes.weak_hash);
	strong_hash.resize(temp_hashes.strong_hash.size());
	std::copy(temp_hashes.strong_hash.begin(), temp_hashes.strong_hash.end(), strong_hash.begin());
}

EncFileMap::EncFileMap() {}
EncFileMap::~EncFileMap() {}

std::list<std::shared_ptr<const Block>> EncFileMap::blocks() const {
	std::list<std::shared_ptr<const Block>> blist;
	auto map_values = offset_blocks_ | boost::adaptors::map_values;
	std::copy(map_values.begin(), map_values.end(), std::back_inserter(blist));
	return blist;
}

std::list<std::shared_ptr<const Block>> EncFileMap::delta(const EncFileMap& old_filemap){
	auto strong_hash_less = [](const decltype(offset_blocks_ | boost::adaptors::map_values)::value_type &block1, const decltype(offset_blocks_ | boost::adaptors::map_values)::value_type &block2){
		return block1->encrypted_hash < block2->encrypted_hash;
	};

	std::list<std::shared_ptr<const Block>> missing_blocks;
	std::set_difference(
			(offset_blocks_ | boost::adaptors::map_values).begin(), (offset_blocks_ | boost::adaptors::map_values).end(),
			(old_filemap.offset_blocks_ | boost::adaptors::map_values).begin(), (old_filemap.offset_blocks_ | boost::adaptors::map_values).end(),
			std::back_inserter(missing_blocks), strong_hash_less);
	return missing_blocks;
}

void EncFileMap::from_protobuf(const EncFileMap_s& filemap_s) {
	size_ = 0;
	maxblocksize_ = filemap_s.maxblocksize() != 0 ? filemap_s.maxblocksize() : 2*1024*1024 ;	// TODO some sort of defaults and sort of protection against maxblocksize=1
	minblocksize_ = filemap_s.minblocksize() != 0 ? filemap_s.minblocksize() : 32*1024;

	for(auto block_s : filemap_s.blocks()){
		auto new_block = std::make_shared<Block>();
		std::copy(block_s.encrypted_hash().begin(), block_s.encrypted_hash().end(), new_block->encrypted_hash.begin());
		new_block->blocksize = block_s.blocksize();
		std::copy(block_s.iv().begin(), block_s.iv().end(), new_block->iv.begin());
		std::copy(block_s.encrypted_hashes().begin(), block_s.encrypted_hashes().end(), new_block->encrypted_hashes_part.begin());

		offset_blocks_.insert(make_pair(size_, new_block));
		size_ += block_s.blocksize();
	}
}

EncFileMap_s EncFileMap::to_protobuf() const {
	EncFileMap_s serialized_map;
	serialized_map.set_maxblocksize(maxblocksize_);
	serialized_map.set_minblocksize(minblocksize_);
	for(auto block : offset_blocks_){
		auto new_block = serialized_map.add_blocks();
		new_block->set_encrypted_hash(block.second->encrypted_hash.data(), block.second->encrypted_hash.size());
		new_block->set_blocksize(block.second->blocksize);
		new_block->set_iv(block.second->iv.data(), block.second->iv.size());
		new_block->set_encrypted_hashes(block.second->encrypted_hashes_part.data(), block.second->encrypted_hashes_part.size());
	}
	return serialized_map;
}

void EncFileMap::from_array(const uint8_t* data, size_t size){
	EncFileMap_s filemap_s; filemap_s.ParseFromArray(data, size);
	from_protobuf(filemap_s);
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

void EncFileMap::print_debug() const {
	int i = 0;
	for(auto block : offset_blocks_){
		print_debug_block(*(block.second), ++i);
	}
}

void EncFileMap::print_debug_block(const Block& block, int num) const {
	if(logger){
		auto encrypted_hash_hex = (block.encrypted_hash | crypto::Hex());
		auto iv_hex = (block.iv | crypto::Hex());
		auto encrypted_hashes_hex = (block.encrypted_hashes_part | crypto::Hex());
		logger->debug() << "N=" << num
				<< " Size=" << block.blocksize
				<< " SHA3(Enc)=" << std::string(std::make_move_iterator(encrypted_hash_hex.begin()), std::make_move_iterator(encrypted_hash_hex.end()))
				<< " IV=" << std::string(std::make_move_iterator(iv_hex.begin()), std::make_move_iterator(iv_hex.end()))

				<< " AES(Hashes(Block))=" << std::string(std::make_move_iterator(encrypted_hashes_hex.begin()), std::make_move_iterator(encrypted_hashes_hex.end()));
	}
}

} /* namespace internals */
} /* namespace librevault */
