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

#include "crypto/RsyncChecksum.h"
#include <botan/aes.h>
#include <botan/botan.h>
#include <botan/keccak.h>
#include <boost/optional.hpp>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <deque>

void initial(){
	Botan::AutoSeeded_RNG rng;
	auto key = rng.random_vec(32);

	std::ifstream input("input.txt");
	std::ofstream output("output.txt");
	std::ofstream output_meta("output_meta.txt");
	std::ofstream output_weak("output_weak.txt");

	std::string rdbuf; rdbuf.resize(LV_MAXCHUNKSIZE, ' ');
	Botan::Keccak_1600 hasher(224);
	do {
		input.read(&*rdbuf.begin(), LV_MAXCHUNKSIZE);
		if(input.gcount() > 0){
			std::string encrypted;
			auto iv = rng.random_vec(16);
			ProcessedChunk proc = processChunk(std::string(&*rdbuf.begin(), input.gcount()), iv, key, encrypted);

			output.write(encrypted.data(), encrypted.size());
			output_meta.write(reinterpret_cast<char*>(&proc.meta), sizeof(ProcessedChunk::ChunkMeta));
			output_weak.write(reinterpret_cast<char*>(&proc.weak_hash), sizeof(uint32_t));
		}
	} while(input.good() && output.good());
}

std::ifstream::pos_type filesize(const char* filename)
{
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

int main(int argc, char** argv){
	Botan::LibraryInitializer init("thread_safe=true");

	if(argc < 2){return 1;}

	if(strcmp(argv[1], "create") == 0){

	}else if(strcmp(argv[1], "update") == 0){	// also known as rechunk
		std::ifstream input("input.txt");
		std::ifstream input_meta("input_meta.txt");
		std::ifstream input_weak("input_weak.txt");
		std::ofstream output_meta("output_meta.txt");
		std::ofstream output_weak("output_weak.txt");

		std::unordered_multimap<weakhash_t, Chunk> old_chunks;
		std::map<offset_t, Chunk> new_recognized_chunks;
		std::map<offset_t, offset_t> new_empty_chunks;

		// Read lvmap. As we are now called librevault, this would be lvmap.
		do {
			Chunk chunk;
			input_meta.read(reinterpret_cast<char*>(&chunk.meta), sizeof(Chunk::Meta));
			input_weak.read(reinterpret_cast<char*>(&chunk.weak_hash), sizeof(weakhash_t));
			if(input_meta.gcount() == sizeof(Chunk::Meta)){
				old_chunks.insert(std::make_pair(chunk.weak_hash, chunk));
			}
		} while(input_meta.good() || input_weak.good());

		// Determine maximum chunk sizes to find
		std::set<uint32_t, std::greater<uint32_t>> chunk_sizes;
		for(auto chunk : old_chunks){chunk_sizes.insert(chunk.second.meta.length);}

		// Read file with searching chunks of necessary size
		new_empty_chunks.insert({0, filesize("input.txt")});

		for(auto chunk_size : chunk_sizes){
			std::vector<char> rdbuf(chunk_size);
			offset_t offset = 0;
			auto chunk_it = new_empty_chunks.begin();
			while(chunk_it != new_empty_chunks.end()){
				if(chunk_it->second < chunk_size)	continue;

				offset = chunk_it->first;
				input.seekg(offset);
				input.read(rdbuf.data(), chunk_size);
				RsyncChecksum weak_hash(rdbuf.data(), rdbuf.size());

				std::pair<decltype(old_chunks)::iterator, decltype(old_chunks)::iterator> equihash_chunks;
				if( (equihash_chunks = old_chunks.equal_range(weak_hash)) != std::make_pair(old_chunks.end(), old_chunks.end())){
					for(auto equihash_chunk = equihash_chunks.first; equihash_chunk != equihash_chunks.second; equihash_chunk++){
						compute_strong_hash()
					}
				}
			}
		}

		//

		std::array<char, LV_MAXCHUNKSIZE>* rdbuf = new std::array<char, LV_MAXCHUNKSIZE>();
		input.read(rdbuf->data(), LV_MAXCHUNKSIZE);
		std::deque<char> data(rdbuf->begin(), rdbuf->end());

		RsyncChecksum hash(rdbuf->data(), input.gcount());
		delete rdbuf;
		do {
			char c;
			input.get(c);
			if(input.gcount() > 0){
				hash
			}
		} while(input_meta.good() || input_weak.good());
	}
}
