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

#include "util.h"
#include "LVMap.h"
#include <boost/log/trivial.hpp>
#include <deque>

LVMap::LVMap(const Botan::SymmetricKey& key) : size(0), key(key) {}

LVMap::~LVMap() {}

LVMap::Chunk LVMap::processChunk(const std::string& binchunk, const Botan::InitializationVector& iv){
	Chunk proc;
	proc.meta.length = (uint32_t)binchunk.size();
	memcpy(proc.meta.iv.data(), &*iv.bits_of().begin(), AES_BLOCKSIZE);
	proc.weak_hash = RsyncChecksum(binchunk);

	std::string encrypted = encrypt(binchunk, key, iv, proc.meta.length % AES_BLOCKSIZE == 0 ? true : false);
	memcpy(proc.meta.strong_hash.data(), compute_shash(encrypted.data(), encrypted.size()).data(), SHASH_LENGTH);

	return proc;
}

std::array<char, SHASH_LENGTH> compute_shash(const char* data, size_t length) const {
	Botan::Keccak_1600 hasher(SHASH_LENGTH*8);

	return hasher.process(reinterpret_cast<const uint8_t*>(data), length);
}

void LVMap::resize(uint64_t new_size) {
}

void LVMap::clear() {
}

void LVMap::create(std::istream& lvfile) {
	std::string rdbuf;

	offset_t offset = 0;
	do {
		rdbuf.resize(LV_MAXCHUNKSIZE);
		lvfile.read(&*rdbuf.begin(), LV_MAXCHUNKSIZE);
		rdbuf.resize(lvfile.gcount());
		if(lvfile.gcount() > 0){
			offset += lvfile.gcount();
			std::string encrypted;
			std::shared_ptr<Chunk> processed_chunk = std::make_shared<Chunk>(processChunk(rdbuf));

			hashed_chunks.insert({processed_chunk->weak_hash, processed_chunk});
			offset_chunks.insert({offset, processed_chunk});
		}
	} while(lvfile.good());

	size = filesize(lvfile);
}

decltype(LVMap::hashed_chunks)::iterator LVMap::match_block(const decltype(hashed_chunks)& chunkset, const std::string& chunkbuf, RsyncChecksum checksum) {
	auto eqhash_blocks = hashed_chunks.equal_range(checksum);
	if(eqhash_blocks != std::make_pair(hashed_chunks.end(), hashed_chunks.end())){
		for(auto eqhash_block = eqhash_blocks.first; eqhash_block != eqhash_blocks.second; eqhash_block++){
			if(compute_shash(chunkbuf.data(), chunkbuf.length()) == eqhash_block->second->meta.strong_hash){
				return eqhash_block;
			}
		}
	}
	return chunkset.end();
}

std::pair<LVMap::offset_t, LVMap::offset_t> LVMap::find_empty_block(offset_t from, offset_t minsize) {
	while(from < size){
		auto it = offset_chunks.lower_bound(from);
		if(it == offset_chunks.end()){
			if(size-from > minsize){
				return {from, size};
			}else break;	// as we reached eof.
		}else if(it->first-from < minsize){
			from = it->first + it->second->meta.length;
		}else{
			return {from, it->first};
		}
	}
	return {0,0};
}

LVMap LVMap::update(std::istream& lvfile) {
	LVMap upd(key); upd.size = filesize(lvfile);
	std::string chunkbuf;
	auto chunks_left = hashed_chunks;	// This will move into upd one by one.

	// Create a set of chunk sizes, sorted in descending order with power of 2 values before other.
	struct greater_pow2_prio {
		bool operator()(const uint32_t& lhs, const uint32_t& rhs){
			bool pow2l = (lhs != 0) && ((lhs & (lhs - 1)) == 0);
			bool pow2r = (rhs != 0) && ((rhs & (rhs - 1)) == 0);
			if( pow2l == pow2r )
				return lhs > rhs;
			else if(pow2l)
				return true;
			return false;
		}
	};
	std::set<uint32_t, greater_pow2_prio> chunk_sizes; for(auto chunk : offset_chunks){chunk_sizes.insert(chunk.second->meta.length);}

	for(auto chunksize : chunk_sizes){
		offset_t offset = 0;
		std::pair<offset_t, offset_t> empty_block;

		empty_block = find_empty_block(offset, chunksize);
		while(empty_block != std::make_pair(0,0)){
			offset = empty_block.first;
			// Block beginning
			chunkbuf.resize(chunksize);
			lvfile.seekg(empty_block.first);
			lvfile.read(&*chunkbuf.begin(), chunksize);
			RsyncChecksum checksum(chunkbuf);

			auto matched_it = match_block(chunks_left, chunkbuf, checksum);
			if(matched_it != chunks_left.end()){
				upd.offset_chunks.insert(std::make_pair(offset, matched_it->second));
				chunks_left.erase(matched_it);
			}else{
				std::deque<char> reading_queue(chunkbuf.begin(), chunkbuf.end());
				do {
					reading_queue.push_back(lvfile.get());
					checksum.roll(reinterpret_cast<uint8_t>(reading_queue.front()), reinterpret_cast<uint8_t>(reading_queue.back()));
					reading_queue.pop_front();
					offset++;

					matched_it = match_block(chunks_left, chunkbuf, checksum);
					if(matched_it != chunks_left.end()){
						upd.offset_chunks.insert(std::make_pair(offset, matched_it->second));
						chunks_left.erase(matched_it);
						break;
					}
				} while(lvfile.tellg() != empty_block.second);
			}
		}
	}

	return upd;
}
