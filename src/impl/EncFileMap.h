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
#ifndef SRC_ENCFILEMAP_H_
#define SRC_ENCFILEMAP_H_

#include "crypto/RsyncChecksum.h"
#include "EncFileMap.pb.h"
#include "pch.h"

namespace cryptodiff {
namespace internals {

static std::shared_ptr<spdlog::logger> logger;
inline void set_logger(std::shared_ptr<spdlog::logger> logger) {cryptodiff::internals::logger = logger;}

enum WeakHashType {RSYNC=0/*, RSYNC64=1*/};
enum StrongHashType {SHA3_224=0, SHA2_224=1};

struct Block {
	blob encrypted_hash;	// 28 bytes
	uint32_t blocksize;	// 4 bytes
	/* IV is being reused as decrypted_hashes_part is considered not equal plaintext's first 32 bytes */
	blob iv;	// 16 bytes.

	weakhash_t weak_hash;	// 4 bytes
	blob strong_hash;	// 28 bytes

	std::array<uint8_t, 32> encrypted_hashes_part;

	void encrypt_hashes(const blob& key);
	void decrypt_hashes(const blob& key);
};

class EncFileMap {
public:
	EncFileMap();
	virtual ~EncFileMap();

	std::list<std::shared_ptr<const Block>> blocks() const;
	std::list<std::shared_ptr<const Block>> delta(const EncFileMap& old_filemap);

	virtual void from_protobuf(const EncFileMap_s& filemap_s);
	EncFileMap_s to_protobuf() const;

	void from_array(const uint8_t* data, size_t size);

	void from_string(const std::string& serialized_str);
	std::string to_string() const;

	void print_debug() const;
	virtual void print_debug_block(const Block& block, int num = 0) const;

	// Getters
	uint32_t get_maxblocksize() const {return maxblocksize_;}
	uint32_t get_minblocksize() const {return minblocksize_;}

	uint64_t get_filesize() const {return size_;}

protected:
	using offset_t = uint64_t;

	// Map data
	uint32_t maxblocksize_ = 0;
	uint32_t minblocksize_ = 0;

	// Other data
	std::map<offset_t, std::shared_ptr<Block>> offset_blocks_;
	offset_t size_ = 0;
};

} /* namespace internals */
} /* namespace librevault */

#endif /* SRC_ENCFILEMAP_H_ */
