/*
 * FileMap.cpp
 *
 *  Created on: 04 февр. 2015 г.
 *      Author: gamepad
 */

#include "FileMap.h"

#include "crypto/StatefulRsyncChecksum.h"
#include <boost/log/trivial.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/asio.hpp>	//htonl, ntohl
#include <list>

Block FileMap::process_block(const std::string& binblock,
		const Botan::InitializationVector& iv) {
	Block proc;
	proc.blocksize = (uint32_t)binblock.size();
	memcpy(proc.iv.data(), &*iv.bits_of().begin(), AES_BLOCKSIZE);

	std::string encrypted_block = encrypt(binblock, key, iv, proc.blocksize % AES_BLOCKSIZE == 0 ? true : false);
	memcpy(proc.encrypted_hash.data(), compute_shash(encrypted_block.data(), encrypted_block.size()).data(), SHASH_LENGTH);

	memcpy(proc.decrypted_hashes_part.strong_hash.data(), compute_shash(binblock.data(), binblock.size()).data(), SHASH_LENGTH);
	proc.decrypted_hashes_part.weak_hash = RsyncChecksum(binblock.begin(), binblock.end());

	std::string encrypted_data_s = encrypt(std::string(reinterpret_cast<char*>(&(proc.decrypted_hashes_part)), sizeof(Block::Hashes)), key, iv, true);
	memcpy(proc.encrypted_hashes_part.data(), encrypted_data_s.data(), encrypted_data_s.size());

	return proc;
}

decltype(FileMap::hashed_blocks)::iterator FileMap::match_block(decltype(hashed_blocks)& blockset, const std::string& blockbuf, RsyncChecksum checksum) {
	auto eqhash_blocks = blockset.equal_range(checksum);
	if(eqhash_blocks != std::make_pair(blockset.end(), blockset.end())){
		for(auto eqhash_block = eqhash_blocks.first; eqhash_block != eqhash_blocks.second; eqhash_block++){
			if(compute_shash(blockbuf.data(), blockbuf.length()) == eqhash_block->second->decrypted_hashes_part.strong_hash){
				//std::cout << "Matched block: " << to_hex(checksum) << " size=" << chunkbuf.size() << std::endl;
				return eqhash_block;
			}
		}
	}
	return hashed_blocks.end();
}

FileMap::FileMap(const Botan::SymmetricKey& key) : key(key) {}
FileMap::~FileMap() {}

void FileMap::create(std::istream& datafile, uint32_t maxblocksize,	uint32_t minblocksize) {
	std::string rdbuf;

	offset_t offset = 0;
	do {
		rdbuf.resize(maxblocksize);
		datafile.read(&*rdbuf.begin(), maxblocksize);
		rdbuf.resize(datafile.gcount());
		if(datafile.gcount() > 0){
			offset += datafile.gcount();
			std::string encrypted;
			std::shared_ptr<Block> processed_chunk = std::make_shared<Block>(process_block(rdbuf));

			hashed_blocks.insert({processed_chunk->decrypted_hashes_part.weak_hash, processed_chunk});
			offset_blocks.insert({offset, processed_chunk});
		}
	} while(datafile.good());

	size = filesize(datafile);
}

FileMap FileMap::update(std::istream& datafile) {
	FileMap upd(key); upd.size = filesize(datafile);

	auto chunks_left = hashed_blocks;       // This will move into upd one by one.

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
	std::set<uint32_t, greater_pow2_prio> chunk_sizes; for(auto chunk : offset_blocks){chunk_sizes.insert(chunk.second->blocksize);}

	//
	using empty_block_t = std::pair<offset_t, offset_t>;    // offset, length.
	std::list<empty_block_t> empty_blocks;  // contains empty_block_t's
	empty_blocks.push_back(empty_block_t(0, size));

	for(auto chunksize : chunk_sizes){
		std::string chunkbuf_s; chunkbuf_s.resize(chunksize);

		for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
			if(empty_block_it->second < chunksize) {empty_block_it++; continue;}

			offset_t offset = empty_block_it->first;

			datafile.seekg(offset);
			datafile.read(&*chunkbuf_s.begin(), chunksize);
			StatefulRsyncChecksum checksum(chunkbuf_s.begin(), chunkbuf_s.end());

			decltype(hashed_blocks)::iterator matched_it;
			do {
				matched_it = match_block(chunks_left, chunkbuf_s, checksum);
				if(matched_it != chunks_left.end()){
					upd.offset_blocks.insert(std::make_pair(offset, matched_it->second));
					upd.hashed_blocks.insert(std::make_pair(checksum, matched_it->second));
					if(offset == empty_block_it->first && chunksize == empty_block_it->second){     // Matched block fits perfectly in empty block
						empty_blocks.erase(empty_block_it++);
					}else if(offset == empty_block_it->first){      // Matched block is in the beginning of empty block
						empty_block_it->first += chunksize;
						empty_block_it->second -= chunksize;
					}else if(offset+chunksize == empty_block_it->first+empty_block_it->second){     // Matched block is in the end of empty block
						empty_block_it->second -= chunksize;
						empty_block_it++;
					}else{  // Matched block is in the middle of empty block
						auto prev_length = empty_block_it->second; auto next_it = empty_block_it;
						empty_block_it->second = offset-empty_block_it->first;
						empty_blocks.insert(++next_it, empty_block_t(offset+chunksize, empty_block_it->first+prev_length));
						empty_block_it++;
					}
					chunks_left.erase(matched_it);
					break;
				}
				if(offset != empty_block_it->first+empty_block_it->second){
					checksum.roll(datafile.get());
					offset++;
				}else break;
			}while(true);
			if(matched_it == chunks_left.end()){
				empty_block_it++;
			}
		}
	}

	for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
		std::cout << "Unmatched block: off=" << empty_block_it->first << " size=" << empty_block_it->second << std::endl;
		empty_block_it++;
	}

	return upd;
}

Block::Hashes FileMap::decrypt_hashes(
		const std::array<char, sizeof(Block::Hashes)>& encrypted_hashes,
		const Botan::InitializationVector& iv, const Botan::SymmetricKey& key) {
	Block::Hashes decrypted_hashes;
	std::string decrypted_string = decrypt(std::string(encrypted_hashes.begin(), encrypted_hashes.end()), key, iv, true);
	memcpy(&decrypted_hashes, decrypted_string.data(), sizeof(Block::Hashes));
	decrypted_hashes.weak_hash = ntohl(decrypted_hashes.weak_hash);
	return decrypted_hashes;
}

std::array<char, sizeof(Block::Hashes)> FileMap::encrypt_hashes(
		Block::Hashes decrypted_hashes,
		const Botan::InitializationVector& iv, const Botan::SymmetricKey& key) {
	decrypted_hashes.weak_hash = htonl(decrypted_hashes.weak_hash);
	auto encrypted_str = encrypt(std::string(reinterpret_cast<char*>(&decrypted_hashes), sizeof(Block::Hashes)), key, iv, true);
	std::array<char, sizeof(Block::Hashes)> enc_array;
	memcpy(enc_array.data(), encrypted_str.data(), sizeof(Block::Hashes));

	return enc_array;
}

void FileMap::print_debug() const {
	int i = 0;
	for(auto chunk : offset_blocks){
		std::cout << "#: " << ++i << " L: " << chunk.second->blocksize << std::endl;
		std::cout << "SHA3(Enc): " << to_hex(chunk.second->encrypted_hash.data()) << std::endl;
		std::cout << "IV: " << to_hex(chunk.second->iv.data()) << std::endl;

		std::cout << "Rsync(Block): " << to_hex(chunk.second->decrypted_hashes_part.weak_hash) << std::endl;
		std::cout << "SHA3(Block): " << to_hex(chunk.second->decrypted_hashes_part.strong_hash.data()) << std::endl << std::endl;
	}
}
