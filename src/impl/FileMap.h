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

#include "EncFileMap.h"
#include "util/File.h"
#include "util/AvailabilityMap.h"
#include "crypto/StatefulRsyncChecksum.h"

namespace cryptodiff {
namespace internals {

class FileMap : public EncFileMap {
public:
	FileMap(blob key);
	virtual ~FileMap();

	void create(const std::string& path);
	FileMap update(const std::string& path);

	void set_blocks(const std::vector<Block>& new_blocks);

protected:
	using block_type = AvailabilityMap<offset_t>::block_type;    // offset, length.
	using weakhash_map = std::unordered_multimap<weakhash_t, std::shared_ptr<DecryptedBlock>>;

	weakhash_map hashed_blocks_;
	blob key_;

	// Subroutines for creating block signature
	DecryptedBlock process_block(const std::vector<uint8_t>& data);

	std::shared_ptr<DecryptedBlock> create_block(File& datafile, block_type unassigned_space, int num = 0);
	void fill_with_map(File& datafile, block_type unassigned_space);
	void create_neighbormap(File& datafile, std::shared_ptr<DecryptedBlock> left, std::shared_ptr<DecryptedBlock> right, block_type unassigned_space);

	// Subroutine for matching blockbuf with defined checksum and existing block signature from blockset.
	weakhash_map::iterator match_block(const StatefulRsyncChecksum& checksum, weakhash_map& blockset);

	void log_matched(weakhash_t checksum, size_t size);
	void log_unmatched(offset_t offset, uint32_t size);
};

} /* namespace internals */
} /* namespace librevault */
