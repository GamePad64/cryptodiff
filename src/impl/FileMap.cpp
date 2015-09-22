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

Block FileMap::process_block(std::vector<uint8_t> data, const IV& iv) {
	Block proc;
	proc.blocksize = data.size();
	proc.iv = iv;

	auto encrypted_block = encrypt(data.data(), data.size(), key, iv, proc.blocksize % AES_BLOCKSIZE == 0 ? true : false);
	proc.encrypted_hash = compute_shash(encrypted_block.data(), encrypted_block.size());

	proc.decrypted_hashes_part.strong_hash = compute_shash(data.data(), data.size());
	proc.decrypted_hashes_part.weak_hash = RsyncChecksum(data.begin(), data.end());

	proc.encrypt_hashes(key);

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

FileMap::FileMap(const Key& key) : key(key) {}
FileMap::~FileMap() {}

void FileMap::create(const std::string& path, uint32_t maxblocksize, uint32_t minblocksize) {
	this->maxblocksize = maxblocksize;
	this->minblocksize = minblocksize;

	File datafile(path);
	size = datafile.size();

	fill_with_map(datafile, {0, size});
}

FileMap FileMap::update(const std::string& path) {
	File datafile(path);

	FileMap upd(key); upd.size = datafile.size();
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
		for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
			if(empty_block_it->second < blocksize) {empty_block_it++; continue;}

			offset_t offset = empty_block_it->first;
			std::vector<uint8_t> blockbuf = datafile.get(offset, blocksize);

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
					checksum.roll(datafile.get(++offset));
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

void FileMap::from_protobuf(const EncFileMap_s& filemap_s) {
	EncFileMap::from_protobuf(filemap_s);
	for(auto block : offset_blocks){
		block.second->decrypt_hashes(key);
		hashed_blocks.insert(std::make_pair(block.second->decrypted_hashes_part.weak_hash, block.second));
	}
}

std::shared_ptr<Block> FileMap::create_block(File& datafile, empty_block_t unassigned_space, int num){
	std::shared_ptr<Block> processed_block = std::make_shared<Block>(process_block(datafile.get(unassigned_space.first, unassigned_space.second)));

	print_debug_block(*processed_block, num);

	hashed_blocks.insert({processed_block->decrypted_hashes_part.weak_hash, processed_block});	// TODO: We have a great race condition here. MUST BE FIXED!
	offset_blocks.insert({unassigned_space.first, processed_block});	// TODO: Also here. Protect hashed_blocks, offset_blocks!
	return processed_block;
}

void FileMap::create_neighbormap(File& datafile,
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

void FileMap::fill_with_map(File& datafile, empty_block_t unassigned_space) {
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
		io_service.post(std::bind(&FileMap::create_block, this, std::ref(datafile), empty_block_t{unassigned_space.first, bytes_to_read}, ++block_count));
		unassigned_space.first += bytes_to_read;
		unassigned_space.second -= bytes_to_read;
	}

	delete work;

	io_service.run();

	for(auto& thread : threads){
		if(thread.joinable()) thread.join();
	}
}

void FileMap::print_debug_block(const Block& block, int num) const {
	BOOST_LOG_TRIVIAL(debug) << "N=" << num
			<< " Size=" << block.blocksize
			<< " SHA3(Enc)=" << to_hex(block.encrypted_hash.data(), SHASH_LENGTH)
			<< " IV=" << to_hex(block.iv.data(), AES_BLOCKSIZE)

			<< " Rsync(Block)=" << to_hex(block.decrypted_hashes_part.weak_hash)
			<< " SHA3(Block)=" << to_hex(block.decrypted_hashes_part.strong_hash.data(), SHASH_LENGTH);
}

} /* namespace internals */
} /* namespace librevault */
