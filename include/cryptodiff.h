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
#define CRYPTODIFF_DLL_EXPORTED __declspec(dllexport)
#elif BUILDING_FILEMAP
#define CRYPTODIFF_DLL_EXPORTED __attribute__((__visibility__("default")))
#elif defined _MSC_VER
#define CRYPTODIFF_DLL_EXPORTED __declspec(dllimport)
#else
#define CRYPTODIFF_DLL_EXPORTED
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

void set_logger(std::shared_ptr<spdlog::logger> logger);

class CRYPTODIFF_DLL_EXPORTED Block {
public:
	Block();
	Block(const Block& block);
	Block(Block&& block);
	Block& operator=(const Block& block);
	Block& operator=(Block&& block);
	~Block();

	struct Hashes {
		uint32_t weak_hash;	// 4 bytes
		std::array<uint8_t, 28> strong_hash;	// 28 bytes
	};

	void encrypt_hashes(const std::vector<uint8_t>& key);
	void decrypt_hashes(const std::vector<uint8_t>& key);

	/* Getters */
	const std::vector<uint8_t>& get_encrypted_hash() const;

	uint32_t get_blocksize() const;
	const std::vector<uint8_t>& get_iv() const;

	const std::array<uint8_t, sizeof(Hashes)>& get_encrypted_hashes_part() const;
	uint32_t get_decrypted_weak_hash() const;
	const std::vector<uint8_t>& get_decrypted_strong_hash() const;

	/* implementation */
	inline void* get_implementation(){return pImpl;}

protected:
	void* pImpl;
};

class CRYPTODIFF_DLL_EXPORTED EncFileMap {
public:
	EncFileMap();
	EncFileMap(const EncFileMap& encfilemap);
	EncFileMap(EncFileMap&& encfilemap);
	EncFileMap& operator=(const EncFileMap& encfilemap);
	EncFileMap& operator=(EncFileMap&& encfilemap);
	virtual ~EncFileMap();

	std::vector<Block> blocks() const;
	std::vector<Block> delta(const EncFileMap& old_filemap);

	void from_array(const uint8_t* data, size_t size);

	void from_string(const std::string& serialized_str);
	std::string to_string() const;

	void print_debug() const;
	void print_debug_block(const Block& block, int count = 0) const;

	uint32_t get_maxblocksize() const;
	uint32_t get_minblocksize() const;
	uint64_t get_filesize() const;

	/* implementation */
	inline void* get_implementation(){return pImpl;}

protected:
	void* pImpl;
};

class CRYPTODIFF_DLL_EXPORTED FileMap : public EncFileMap {
protected:
	FileMap();
public:
	FileMap(const std::vector<uint8_t>& key);
	virtual ~FileMap();

	void create(const std::string& datafile, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	FileMap update(const std::string& datafile);
};

} /* namespace filemap */

#endif /* CRYPTODIFF_H_ */
