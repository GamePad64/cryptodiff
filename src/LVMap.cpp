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
#include <boost/circular_buffer.hpp>
#include <list>

LVMap::LVMap() : size(0) {}
LVMap::LVMap(const Botan::SymmetricKey& key) : size(0) {setKey(key);}

LVMap::~LVMap() {}

LVMap::Chunk LVMap::processChunk(const std::string& binchunk, const Botan::InitializationVector& iv){
	Chunk proc;
	proc.meta.length = (uint32_t)binchunk.size();
	memcpy(proc.meta.iv.data(), &*iv.bits_of().begin(), AES_BLOCKSIZE);
	proc.weak_hash = RsyncChecksum(binchunk);

	std::string encrypted = encrypt(binchunk, key, iv, proc.meta.length % AES_BLOCKSIZE == 0 ? true : false);
	memcpy(proc.meta.strong_hash.data(), compute_shash(binchunk.data(), binchunk.size()).data(), SHASH_LENGTH);

	return proc;
}

std::array<char, SHASH_LENGTH> LVMap::compute_shash(const char* data, size_t length) const {
	Botan::Keccak_1600 hasher(SHASH_LENGTH*8);

	auto hash = hasher.process(reinterpret_cast<const uint8_t*>(data), length);
	std::array<char, SHASH_LENGTH> hash_array; memcpy((void*)&hash_array, hash.data(), SHASH_LENGTH);
	return hash_array;
}

void LVMap::setSize(uint64_t new_size) {
}

void LVMap::clear() {
}

void LVMap::create(std::istream& datafile) {
	std::string rdbuf;

	offset_t offset = 0;
	do {
		rdbuf.resize(LV_MAXCHUNKSIZE);
		datafile.read(&*rdbuf.begin(), LV_MAXCHUNKSIZE);
		rdbuf.resize(datafile.gcount());
		if(datafile.gcount() > 0){
			offset += datafile.gcount();
			std::string encrypted;
			std::shared_ptr<Chunk> processed_chunk = std::make_shared<Chunk>(processChunk(rdbuf));

			hashed_chunks.insert({processed_chunk->weak_hash, processed_chunk});
			offset_chunks.insert({offset, processed_chunk});
		}
	} while(datafile.good());

	size = filesize(datafile);
}

decltype(LVMap::hashed_chunks)::iterator LVMap::match_block(decltype(hashed_chunks)& chunkset, const std::string& chunkbuf, RsyncChecksum checksum) {
	auto eqhash_blocks = hashed_chunks.equal_range(checksum);
	if(eqhash_blocks != std::make_pair(hashed_chunks.end(), hashed_chunks.end())){
		for(auto eqhash_block = eqhash_blocks.first; eqhash_block != eqhash_blocks.second; eqhash_block++){
			if(compute_shash(chunkbuf.data(), chunkbuf.length()) == eqhash_block->second->meta.strong_hash){
				std::cout << "Matched block: " << to_hex(checksum) << " size=" << chunkbuf.size() << std::endl;
				return eqhash_block;
			}
		}
	}
	return hashed_chunks.end();
}

std::pair<LVMap::offset_t, LVMap::offset_t> LVMap::find_empty_block(offset_t from, offset_t minsize) {
	while(from < size){
		auto it = offset_chunks.lower_bound(from);
		if(it == offset_chunks.end()){
			if(size-from >= minsize){
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

LVMap LVMap::update(std::istream& datafile) {
	LVMap upd(key); upd.size = filesize(datafile);

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

	//
	using empty_block_t = std::pair<offset_t, offset_t>;	// offset, length.
	std::list<empty_block_t> empty_blocks;	// contains empty_block_t's
	empty_blocks.push_back(empty_block_t(0, size));

	for(auto chunksize : chunk_sizes){
		std::string chunkbuf_s; chunkbuf_s.resize(chunksize);
		boost::circular_buffer<char> chunkbuf_cb(chunksize);

		for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
			if(empty_block_it->second < chunksize) continue;

			offset_t offset = empty_block_it->first;

			datafile.seekg(offset);
			datafile.read(&*chunkbuf_s.begin(), chunksize);
			chunkbuf_cb.assign(chunkbuf_s.begin(), chunkbuf_s.end());
			RsyncChecksum checksum(chunkbuf_s);

			auto matched_it = match_block(chunks_left, chunkbuf_s, checksum);	// TODO: Matches the same block.
			do {
				if(matched_it != chunks_left.end()){
					upd.offset_chunks.insert(std::make_pair(offset, matched_it->second));
					upd.hashed_chunks.insert(std::make_pair(checksum, matched_it->second));
					if(offset == empty_block_it->first && chunksize == empty_block_it->second){	// Matched block fits perfectly in empty block
						empty_blocks.erase(empty_block_it++);
					}else if(offset == empty_block_it->first){	// Matched block is in the beginning of empty block
						empty_block_it->first += chunksize;
						empty_block_it->second -= chunksize;
					}else if(offset+chunksize == empty_block_it->first+empty_block_it->second){	// Matched block is in the end of empty block
						empty_block_it->second -= chunksize;
						empty_block_it++;
					}else{	// Matched block is in the middle of empty block
						auto prev_length = empty_block_it->second; auto next_it = empty_block_it;
						empty_block_it->second = offset-empty_block_it->first;
						empty_blocks.insert(++next_it, empty_block_t(offset+chunksize, empty_block_it->first+prev_length));
						empty_block_it++;
					}
					chunks_left.erase(matched_it);
					break;
				}
				if(datafile.tellg() != empty_block_it->first+empty_block_it->second){
					char old_char = chunkbuf_cb.front();
					chunkbuf_cb.push_back(datafile.get());
					checksum.roll(reinterpret_cast<uint8_t&>(old_char), reinterpret_cast<uint8_t&>(*(chunkbuf_cb.end()-1)));
					offset++;
				}else break;
			}while(true);
			if(matched_it == chunks_left.end()){
				empty_block_it++;
			}
		}

		/*// Refactor below.
		while(empty_block != std::pair<offset_t, offset_t>(0,0)){
			// Block beginning
			chunkbuf.resize(chunksize);
			datafile.seekg(empty_block.first);
			datafile.read(&*chunkbuf.begin(), chunksize);
			RsyncChecksum checksum(chunkbuf);

			auto matched_it = match_block(chunks_left, chunkbuf, checksum);	// TODO: Matches the same block.
			if(matched_it != boost::optional<decltype(hashed_chunks)::iterator>()){
				upd.offset_chunks.insert(std::make_pair(offset, matched_it.get()->second));
				upd.hashed_chunks.insert(std::make_pair(checksum, matched_it.get()->second));
				//chunks_left.erase(matched_it.get());
			}else{
				std::deque<char> reading_queue(chunkbuf.begin(), chunkbuf.end());
				do {
					reading_queue.push_back(datafile.get());
					checksum.roll(reinterpret_cast<uint8_t&>(reading_queue.front()), reinterpret_cast<uint8_t&>(reading_queue.back()));
					reading_queue.pop_front();
					offset++;

					matched_it = match_block(chunks_left, std::string(reading_queue.begin(), reading_queue.end()), checksum);
					if(matched_it != boost::optional<decltype(hashed_chunks)::iterator>()){
						upd.offset_chunks.insert(std::make_pair(offset, matched_it.get()->second));
						upd.hashed_chunks.insert(std::make_pair(checksum, matched_it.get()->second));
						//chunks_left.erase(matched_it.get());
						break;
					}
				} while(datafile.tellg() != empty_block.second);
			}
			empty_block = upd.find_empty_block(offset+chunksize, chunksize);
		}*/
	}

	for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
		std::cout << "Unmatched block: off=" << empty_block_it->first << " size=" << empty_block_it->second << std::endl;
		empty_block_it++;
	}

	return upd;
}

void LVMap::from_file(std::istream& lvfile){
	size = 0;
	do {
		std::shared_ptr<Chunk> chunk = std::make_shared<Chunk>();
		lvfile.read(reinterpret_cast<char*>(chunk.get()), sizeof(Chunk));

		if(lvfile.gcount() == sizeof(Chunk)){
			hashed_chunks.insert(std::make_pair(chunk->weak_hash, chunk));
			offset_chunks.insert(std::make_pair(size, chunk));
			size += chunk->meta.length;
		}
	} while(lvfile.good());
}

void LVMap::to_file(std::ostream& lvfile){
	for(auto chunk : offset_chunks){
		lvfile.write(reinterpret_cast<char*>(chunk.second.get()), sizeof(Chunk));
	}
}

void LVMap::print_debug(){
	int i = 0;
	for(auto chunk : offset_chunks){
		std::cout << "#: " << ++i << " L: " << chunk.second->meta.length << std::endl;
		std::cout << "Rsync: " << to_hex(chunk.second->weak_hash) << std::endl;
		std::cout << "SHA-3: " << to_hex(chunk.second->meta.strong_hash.data()) << std::endl;
		std::cout << "IV: " << to_hex(chunk.second->meta.iv.data()) << std::endl << std::endl;
	}
}
