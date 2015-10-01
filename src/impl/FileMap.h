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
#include "File.h"
#include <cryptopp/osrng.h>
#include <unordered_map>

namespace cryptodiff {
namespace internals {

class FileMap : public EncFileMap {
public:
	FileMap(blob key);
	virtual ~FileMap();

	void create(const std::string& path, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	FileMap update(const std::string& path);

	virtual void from_protobuf(const EncFileMap_s& filemap_s);

	virtual void print_debug_block(const Block& block, int num = 0) const;

protected:
	using empty_block_t = std::pair<offset_t, uint32_t>;    // offset, length.

	std::unordered_multimap<weakhash_t, std::shared_ptr<Block>> hashed_blocks_;

	blob key_;

	// Subroutines for creating block signature
	Block process_block(const std::vector<uint8_t>& data);

	//
	std::shared_ptr<Block> create_block(File& datafile, empty_block_t unassigned_space, int num = 0);
	void fill_with_map(File& datafile, empty_block_t unassigned_space);
	void create_neighbormap(File& datafile, std::shared_ptr<Block> left, std::shared_ptr<Block> right, empty_block_t unassigned_space);

	// Subroutine for matching blockbuf with defined checksum and existing block signature from blockset.
	decltype(hashed_blocks_)::iterator match_block(const blob& datablock, decltype(hashed_blocks_)& blockset, weakhash_t checksum);

	void log_matched(weakhash_t checksum, size_t size);
};

} /* namespace internals */
} /* namespace librevault */

#endif /* SRC_FILEMAP_H_ */
