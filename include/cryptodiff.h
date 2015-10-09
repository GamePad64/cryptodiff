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
#ifndef CRYPTODIFF_H_
#define CRYPTODIFF_H_

#if BUILDING_CRYPTODIFF && defined _MSC_VER
#define CRYPTODIFF_EXPORTED __declspec(dllexport)
#elif BUILDING_FILEMAP
#define CRYPTODIFF_EXPORTED __attribute__((__visibility__("default")))
#elif defined _MSC_VER
#define CRYPTODIFF_EXPORTED __declspec(dllimport)
#else
#define CRYPTODIFF_EXPORTED
#endif

#include <cstdint>
#include <iostream>
#include <array>
#include <vector>
#include <memory>

namespace spdlog {
class logger;
} /* namespace spdlog */

namespace cryptodiff {

enum WeakHashType : uint8_t {RSYNC=0/*, RSYNC64=1*/};
enum StrongHashType : uint8_t {SHA3_224=0, SHA2_224=1};

void CRYPTODIFF_EXPORTED set_logger(std::shared_ptr<spdlog::logger> logger);

std::vector<uint8_t> CRYPTODIFF_EXPORTED encrypt_block(const std::vector<uint8_t>& datablock, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
std::vector<uint8_t> CRYPTODIFF_EXPORTED decrypt_block(const std::vector<uint8_t>& datablock, uint32_t blocksize, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

std::vector<uint8_t> CRYPTODIFF_EXPORTED compute_strong_hash(const std::vector<uint8_t>& data, StrongHashType type);

struct CRYPTODIFF_EXPORTED Block {
	std::vector<uint8_t> encrypted_data_hash_;	// >=28 bytes; =28 bytes with SHA3_224 or SHA2_224
	std::vector<uint8_t> encrypted_rsync_hashes_;	// >=32 bytes
	uint32_t blocksize_;	// 4 bytes.
	std::vector<uint8_t> iv_;	// =16 bytes, IV is being reused as decrypted_hashes_part is considered not equal plaintext's first 32 bytes
};

class CRYPTODIFF_EXPORTED EncFileMap {
public:
	EncFileMap();
	EncFileMap(const EncFileMap& encfilemap);
	EncFileMap(EncFileMap&& encfilemap);
	EncFileMap& operator=(const EncFileMap& encfilemap);
	EncFileMap& operator=(EncFileMap&& encfilemap);
	virtual ~EncFileMap();

	std::vector<Block> delta(const EncFileMap& old_filemap);

	std::string debug_string() const;
	uint64_t filesize() const;

	// Getters
	std::vector<Block> blocks() const;
	uint32_t maxblocksize() const;
	uint32_t minblocksize() const;
	StrongHashType strong_hash_type() const;
	WeakHashType weak_hash_type() const;

	// Setters
	void set_blocks(const std::vector<Block>&);
	void set_maxblocksize(uint32_t);
	void set_minblocksize(uint32_t);
	void set_strong_hash_type(StrongHashType);
	void set_weak_hash_type(WeakHashType);

	/* implementation */
	inline void* get_implementation(){return pImpl;}

protected:
	void* pImpl;
};

class CRYPTODIFF_EXPORTED FileMap : public EncFileMap {
protected:
	FileMap();
public:
	FileMap(std::vector<uint8_t> key);
	virtual ~FileMap();

	void create(const std::string& datafile);
	FileMap update(const std::string& datafile);
};

} /* namespace filemap */

#endif /* CRYPTODIFF_H_ */
