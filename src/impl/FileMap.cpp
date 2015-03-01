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
#include "FileMap.h"

#include "crypto/StatefulRsyncChecksum.h"
#include <boost/log/trivial.hpp>
#include <boost/asio.hpp>
#include <list>
#include <thread>
#include <set>
#include <mutex>

namespace cryptodiff {
namespace internals {

Block FileMap::process_block(const uint8_t* data, size_t size,
		const iv_t& iv) {
	Block proc;
	proc.blocksize = size;
	proc.iv = iv;

	auto encrypted_block = encrypt(data, size, key, iv, proc.blocksize % AES_BLOCKSIZE == 0 ? true : false);
	proc.encrypted_hash = compute_shash(encrypted_block.data(), encrypted_block.size());

	proc.decrypted_hashes_part.strong_hash = compute_shash(data, size);
	proc.decrypted_hashes_part.weak_hash = RsyncChecksum(data, data+size);

	proc.encrypted_hashes_part = encrypt_hashes(proc.decrypted_hashes_part, iv, key);

	return proc;
}

decltype(FileMap::hashed_blocks)::iterator FileMap::match_block(const uint8_t* data, size_t size, decltype(hashed_blocks)& blockset, weakhash_t checksum) {
	auto eqhash_blocks = blockset.equal_range(checksum);
	if(eqhash_blocks != std::make_pair(blockset.end(), blockset.end())){
		for(auto eqhash_block = eqhash_blocks.first; eqhash_block != eqhash_blocks.second; eqhash_block++){
			if(compute_shash(data, size) == eqhash_block->second->decrypted_hashes_part.strong_hash){
				std::cout << "Matched block: " << to_hex(checksum) << " size=" << size << std::endl;
				return eqhash_block;
			}
		}
	}
	return hashed_blocks.end();
}

FileMap::FileMap(const key_t& key) : key(key) {}
FileMap::~FileMap() {}

void FileMap::create(std::istream& datafile, uint32_t maxblocksize, uint32_t minblocksize) {
	this->maxblocksize = maxblocksize;
	this->minblocksize = minblocksize;
	size = filesize(datafile);

	fill_with_map(datafile, {0, size});
}

FileMap FileMap::update(std::istream& datafile) {
	FileMap upd(key); upd.size = filesize(datafile);
	upd.maxblocksize = maxblocksize;
	upd.minblocksize = minblocksize;

	auto blocks_left = hashed_blocks;       // This will move into upd one by one.

	// Create a set of block sizes, sorted in descending order with power of 2 values before others.
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
	std::set<uint32_t, greater_pow2_prio> block_sizes; for(auto block : offset_blocks){block_sizes.insert(block.second->blocksize);}

	//
	std::list<empty_block_t> empty_blocks;  // contains empty_block_t's
	empty_blocks.push_back(empty_block_t(0, upd.size));

	for(auto blocksize : block_sizes){
		std::vector<uint8_t> blockbuf; blockbuf.resize(blocksize);

		for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
			if(empty_block_it->second < blocksize) {empty_block_it++; continue;}

			offset_t offset = empty_block_it->first;

			datafile.seekg(offset);
			datafile.read((char*)blockbuf.data(), blocksize);
			StatefulRsyncChecksum checksum(blockbuf.begin(), blockbuf.end());

			decltype(hashed_blocks)::iterator matched_it;
			do {
				matched_it = match_block((uint8_t*)blockbuf.data(), blockbuf.size(), blocks_left, checksum);
				if(matched_it != blocks_left.end()){
					upd.offset_blocks.insert(std::make_pair(offset, matched_it->second));
					upd.hashed_blocks.insert(std::make_pair(checksum, matched_it->second));
					if(offset == empty_block_it->first && blocksize == empty_block_it->second){     // Matched block fits perfectly in empty block
						empty_blocks.erase(empty_block_it++);
					}else if(offset == empty_block_it->first){      // Matched block is in the beginning of empty block
						empty_block_it->first += blocksize;
						empty_block_it->second -= blocksize;
					}else if(offset+blocksize == empty_block_it->first+empty_block_it->second){     // Matched block is in the end of empty block
						empty_block_it->second -= blocksize;
						empty_block_it++;
					}else{  // Matched block is in the middle of empty block
						auto prev_length = empty_block_it->second; auto next_it = empty_block_it;
						empty_block_it->second = offset-empty_block_it->first;
						empty_blocks.insert(++next_it, empty_block_t(offset+blocksize, empty_block_it->first+prev_length));
						empty_block_it++;
					}
					blocks_left.erase(matched_it);
					break;
				}
				if(offset != empty_block_it->first+empty_block_it->second){
					checksum.roll(datafile.get());
					offset++;
				}else break;
			}while(true);
			if(matched_it == blocks_left.end()){
				empty_block_it++;
			}
		}
	}

	for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); empty_block_it++){
		std::cout << "Unmatched block: off=" << empty_block_it->first << " size=" << empty_block_it->second << std::endl;
		auto lb_block = upd.offset_blocks.lower_bound(empty_block_it->first);
		std::shared_ptr<Block> left_blk, right_blk;
		if(lb_block != upd.offset_blocks.end()){
			right_blk = lb_block->second;
		}
		if(lb_block != upd.offset_blocks.begin()){
			--lb_block;
			left_blk = lb_block->second;
		}

		upd.create_neighbormap(datafile, left_blk, right_blk, *empty_block_it);
	}

	return upd;
}

Block::Hashes FileMap::decrypt_hashes(
		const std::array<uint8_t, sizeof(Block::Hashes)>& encrypted_hashes,
		const iv_t& iv, const key_t& key) {
	Block::Hashes decrypted_hashes;
	auto decrypted_vector = decrypt(encrypted_hashes.data(), encrypted_hashes.size(), key, iv, true);

	std::move(decrypted_vector.begin(), decrypted_vector.end(), (uint8_t*)&decrypted_hashes);
	decrypted_hashes.weak_hash = ntohl(decrypted_hashes.weak_hash);

	return decrypted_hashes;
}

std::array<uint8_t, sizeof(Block::Hashes)> FileMap::encrypt_hashes(
		Block::Hashes decrypted_hashes,
		const iv_t& iv, const key_t& key) {
	decrypted_hashes.weak_hash = htonl(decrypted_hashes.weak_hash);
	auto encrypted_vector = encrypt(reinterpret_cast<uint8_t*>(&decrypted_hashes), sizeof(Block::Hashes), key, iv, true);

	std::array<uint8_t, sizeof(Block::Hashes)> enc_array;
	std::move(encrypted_vector.begin(), encrypted_vector.end(), enc_array.begin());

	return enc_array;
}

void FileMap::from_protobuf(const EncFileMap_s& filemap_s) {
	EncFileMap::from_protobuf(filemap_s);
	for(auto block : offset_blocks){
		block.second->decrypted_hashes_part = decrypt_hashes(
				block.second->encrypted_hashes_part, block.second->iv, key);
		hashed_blocks.insert(std::make_pair(block.second->decrypted_hashes_part.weak_hash, block.second));
	}
}

std::shared_ptr<Block> FileMap::create_block(std::istream& datafile, empty_block_t unassigned_space){
	std::vector<char> rdbuf(size);

	datafile.seekg(unassigned_space.first);
	datafile.read(&*rdbuf.begin(), unassigned_space.second);

	std::shared_ptr<Block> processed_block = std::make_shared<Block>(process_block((uint8_t*)rdbuf.data(), rdbuf.size()));

	print_debug_block(*processed_block);

	hashed_blocks.insert({processed_block->decrypted_hashes_part.weak_hash, processed_block});
	offset_blocks.insert({unassigned_space.first, processed_block});
	return processed_block;
}

void FileMap::create_neighbormap(std::istream& datafile,
		std::shared_ptr<Block> left, std::shared_ptr<Block> right,
		empty_block_t unassigned_space) {
	if(!right && !left){
		fill_with_map(datafile, unassigned_space);
	}else if(!right){	// Append in the end.
		if(left->blocksize < maxblocksize){
			unassigned_space.first -= left->blocksize;
			unassigned_space.second += left->blocksize;
			hashed_blocks.erase(left->decrypted_hashes_part.weak_hash);
			offset_blocks.erase(unassigned_space.first);
		}
		fill_with_map(datafile, unassigned_space);
	}else{	// FIXME: Dirty hack. We need some more logic here.
		fill_with_map(datafile, unassigned_space);
	}
}

void FileMap::fill_with_map(std::istream& datafile, empty_block_t unassigned_space) {
	if(unassigned_space.second == 0) return;

	boost::asio::io_service io_service;
	auto work = new boost::asio::io_service::work(io_service);

	std::vector<std::thread> threads;
	std::mutex datafile_lock;

#ifndef SINGLE_THREADED
	// Threaded initialization
	for(auto threadnum = 0; threadnum < (std::thread::hardware_concurrency() == 0 ? 0 : std::thread::hardware_concurrency()-1); threadnum++){
		threads.emplace_back(std::bind(static_cast<size_t (boost::asio::io_service::*) ()>(&boost::asio::io_service::run), &io_service));
	}
#endif // SINGLE_THREADED

	int block_count = 0;
	while(unassigned_space.second != 0){
		size_t bytes_to_read = std::min(unassigned_space.second, maxblocksize);
		io_service.post(std::bind([this](offset_t offset, size_t size, int block_count, std::mutex* datafile_lock, std::istream* file){
			std::vector<char> rdbuf(size);

			datafile_lock->lock();
			file->seekg(offset);
			file->read(&*rdbuf.begin(), size);
			datafile_lock->unlock();

			std::shared_ptr<Block> processed_block = std::make_shared<Block>(process_block((uint8_t*)rdbuf.data(), rdbuf.size()));

			print_debug_block(*processed_block, block_count);

			hashed_blocks.insert({processed_block->decrypted_hashes_part.weak_hash, processed_block});
			offset_blocks.insert({offset, processed_block});
		}, unassigned_space.first, bytes_to_read, ++block_count, &datafile_lock, &datafile));
		unassigned_space.first += bytes_to_read;
		unassigned_space.second -= bytes_to_read;
	}

	delete work;

	io_service.run();

	for(auto& thread : threads){
		if(thread.joinable()) thread.join();
	}
}

void FileMap::print_debug_block(const Block& block, int count) const {
	std::cout << "#: " << count << " L: " << block.blocksize << std::endl;
	std::cout << "SHA3(Enc): " << to_hex(block.encrypted_hash.data(), SHASH_LENGTH) << std::endl;
	std::cout << "IV: " << to_hex(block.iv.data(), AES_BLOCKSIZE) << std::endl;

	std::cout << "Rsync(Block): " << to_hex(block.decrypted_hashes_part.weak_hash) << std::endl;
	std::cout << "SHA3(Block): " << to_hex(block.decrypted_hashes_part.strong_hash.data(), SHASH_LENGTH) << std::endl << std::endl;
}

} /* namespace internals */
} /* namespace librevault */
