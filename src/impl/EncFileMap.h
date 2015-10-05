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
#include "pch.h"
#include "../../include/cryptodiff.h"
#include "crypto/RsyncChecksum.h"

namespace cryptodiff {
namespace internals {

static std::shared_ptr<spdlog::logger> logger;
inline void set_logger(std::shared_ptr<spdlog::logger> logger) {cryptodiff::internals::logger = logger;}

struct DecryptedBlock {
	Block enc_block_;

	weakhash_t weak_hash_ = 0;	// 4 bytes
	blob strong_hash_ = {};	// 28 bytes

	void encrypt_hashes(const blob& key);
	void decrypt_hashes(const blob& key);

	std::string debug_string() const;
};

class EncFileMap {
public:
	EncFileMap();
	virtual ~EncFileMap();

	std::vector<Block> delta(const EncFileMap& old_filemap);

	virtual void print_debug_block(const DecryptedBlock& block, int num = 0) const;

	std::string debug_string() const;
	uint64_t filesize() const {return size_;}

	// Getters
	std::vector<Block> blocks() const;
	uint32_t maxblocksize() const {return maxblocksize_;}
	uint32_t minblocksize() const {return minblocksize_;}
	StrongHashType strong_hash_type() const {return strong_hash_type_;}
	WeakHashType weak_hash_type() const {return weak_hash_type_;}

	// Setters
	virtual void set_blocks(const std::vector<Block>& new_blocks);
	void set_maxblocksize(uint32_t new_maxblocksize) {maxblocksize_ = new_maxblocksize;}
	void set_minblocksize(uint32_t new_minblocksize) {minblocksize_ = new_minblocksize;}
	void set_strong_hash_type(StrongHashType new_strong_hash_type) {strong_hash_type_ = new_strong_hash_type;}
	void set_weak_hash_type(WeakHashType new_weak_hash_type) {weak_hash_type_ = new_weak_hash_type;}

protected:
	using offset_t = uint64_t;

	// Map data
	uint32_t maxblocksize_ = 2*1024*1024;
	uint32_t minblocksize_ = 0;

	StrongHashType strong_hash_type_ = SHA3_224;
	WeakHashType weak_hash_type_ = RSYNC;

	// Other data
	std::map<offset_t, std::shared_ptr<DecryptedBlock>> offset_blocks_;
	offset_t size_ = 0;
};

} /* namespace internals */
} /* namespace librevault */
