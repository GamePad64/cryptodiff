/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SRC_LVMAP_H_
#define SRC_LVMAP_H_

#include "crypto/RsyncChecksum.h"
#include <boost/optional.hpp>
#include <botan/symkey.h>
#include <botan/rng.h>
#include <botan/botan.h>
#include <string>
#include <map>
#include <array>
#include <unordered_map>
#include <cstdint>
#include <iostream>
#include <memory>

constexpr size_t LV_MAXBLOCKSIZE = 2*1024*1024;	// 2 MiB
constexpr size_t LV_MINBLOCKSIZE = 32 * 1024;	// 32 KiB
constexpr size_t AES_BLOCKSIZE = 16;
constexpr size_t AES_KEYSIZE = 32;
constexpr size_t SHASH_LENGTH = 28;

class LVMap {
	using offset_t = uint64_t;

	struct Header {
		const std::array<char, 4> magic = {'L', 'V', 'S', '\n'};
		uint32_t maxblocksize;
		uint32_t minblocksize;
	};	// 12 bytes
	struct Chunk {
		struct Meta {
			std::array<char, SHASH_LENGTH> encrypted_hash;	// 28 bytes
			uint32_t blocksize;	// 4 bytes
			std::array<char, AES_BLOCKSIZE> iv;	// 16 bytes
		} meta;	// 48 bytes
		struct Encrypted {
			weakhash_t weak_hash;	// 4 bytes
			std::array<char, SHASH_LENGTH> strong_hash;	// 28 bytes
		} encrypted;	// 32 bytes = 2 AES blocks without padding
	};	// 80 bytes.

	std::unordered_multimap<weakhash_t, std::shared_ptr<Chunk>> hashed_blocks;
	std::map<offset_t, std::shared_ptr<Chunk>> offset_blocks;

	offset_t size;

	Botan::SymmetricKey key;

	Chunk process_block(const std::string& binchunk){Botan::AutoSeeded_RNG rng; auto iv = rng.random_vec(AES_BLOCKSIZE); return process_block(binchunk, iv);};
	Chunk process_block(const std::string& binchunk, const Botan::InitializationVector& iv);

	decltype(hashed_blocks)::iterator match_block(decltype(hashed_blocks)& chunkset, const std::string& chunkbuf, RsyncChecksum checksum);

	std::array<char, SHASH_LENGTH> compute_shash(const char* data, size_t length) const;
public:
	LVMap();
	LVMap(const Botan::SymmetricKey& key);
	virtual ~LVMap();

	void create(std::istream& datafile);
	LVMap update(std::istream& datafile);

	void from_file(std::istream& lvfile);
	void to_file(std::ostream& lvfile);

	void print_debug();
};

#endif /* SRC_LVMAP_H_ */
