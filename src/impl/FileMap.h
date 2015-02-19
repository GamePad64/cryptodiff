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
#pragma once
#ifndef SRC_FILEMAP_H_
#define SRC_FILEMAP_H_

#include "EncFileMap.h"
#include <unordered_map>

namespace cryptodiff {
namespace internals {

class FileMap: public EncFileMap {
protected:
	using empty_block_t = std::pair<offset_t, uint32_t>;    // offset, length.

	std::unordered_multimap<weakhash_t, std::shared_ptr<Block>> hashed_blocks;

	Botan::SymmetricKey key;

	// Encrypt
	Block::Hashes decrypt_hashes(const std::array<uint8_t, sizeof(Block::Hashes)>& encrypted_hashes, const Botan::InitializationVector& iv, const Botan::SymmetricKey& key);
	std::array<uint8_t, sizeof(Block::Hashes)> encrypt_hashes(Block::Hashes decrypted_hashes, const Botan::InitializationVector& iv, const Botan::SymmetricKey& key);

	// Subroutines for creating block signature
	Block process_block(const uint8_t* data, size_t size){Botan::AutoSeeded_RNG rng; auto iv = rng.random_vec(AES_BLOCKSIZE); return process_block(data, size, iv);};
	Block process_block(const uint8_t* data, size_t size, const Botan::InitializationVector& iv);

	//
	std::shared_ptr<Block> create_block(std::istream& datafile, empty_block_t unassigned_space);
	void fill_with_map(std::istream& datafile, empty_block_t unassigned_space);
	void create_neighbormap(std::istream& datafile, std::shared_ptr<Block> left, std::shared_ptr<Block> right, empty_block_t unassigned_space);

	// Subroutine for matching blockbuf with defined checksum and existing block signature from blockset.
	decltype(hashed_blocks)::iterator match_block(const uint8_t* data, size_t size, decltype(hashed_blocks)& blockset, weakhash_t checksum);
public:
	FileMap(const Botan::SymmetricKey& key);
	FileMap(const std::array<uint8_t, AES_KEYSIZE>& key);
	virtual ~FileMap();

	void create(std::istream& datafile, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	FileMap update(std::istream& datafile);

	virtual void from_protobuf(const EncFileMap_s& filemap_s);

	virtual void print_debug_block(const Block& block, int count = 0) const;
};

} /* namespace internals */
} /* namespace librevault */

#endif /* SRC_FILEMAP_H_ */
