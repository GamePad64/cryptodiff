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

#include <string>
#include <map>
#include <unordered_map>

constexpr size_t LV_MAXCHUNKSIZE = 4096;
constexpr size_t LV_MINCHUNKSIZE = 256;
constexpr size_t AES_BLOCKSIZE = 16;
constexpr size_t SHASH_LENGTH = 28;

class LVMap {
	using offset_t = uint64_t;

	struct Chunk {
		struct Meta {
			std::array<char, SHASH_LENGTH> strong_hash; uint32_t length;	// 32 bytes
			std::array<char, AES_BLOCKSIZE> iv;
		} meta;	// 48 bytes
		weakhash_t weak_hash;	// 4 bytes
	};

	std::unordered_multimap<weakhash_t, std::shared_ptr<Chunk>> hashed_chunks;
	std::map<offset_t, std::shared_ptr<Chunk>> offset_chunks;

	offset_t size;

	Botan::SymmetricKey key;

	Chunk processChunk(const std::string& binchunk){Botan::AutoSeeded_RNG rng; auto iv = rng.random_vec(AES_BLOCKSIZE); return processChunk(binchunk, iv);};
	Chunk processChunk(const std::string& binchunk, const Botan::InitializationVector& iv);

	decltype(hashed_chunks)::iterator match_block(const decltype(hashed_chunks)& chunkset, const std::string& chunkbuf, RsyncChecksum checksum);

	std::array<char, SHASH_LENGTH> compute_shash(const char* data, size_t length) const;
	std::pair<offset_t, offset_t> find_empty_block(offset_t from, offset_t minsize);
public:
	LVMap(const Botan::SymmetricKey& key);
	virtual ~LVMap();

	void resize(uint64_t new_size);
	void clear();

	void create(std::istream& lvfile);
	LVMap update(std::istream& lvfile);
};

#endif /* SRC_LVMAP_H_ */
