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

#include "crypto/RsyncChecksum.h"
#include "crypto/StatefulRsyncChecksum.h"

namespace cryptodiff {
namespace internals {

FileMap::FileMap(blob key) : EncFileMap(), key_(std::move(key)) {}
FileMap::~FileMap() {}

void FileMap::create(const std::string& path) {
	File datafile(path);
	size_ = datafile.size();

	fill_with_map(datafile, {0, size_});
}

FileMap FileMap::update(const std::string& path) {
	File datafile(path);

	FileMap upd(key_); upd.size_ = datafile.size();
	upd.maxblocksize_ = maxblocksize_;
	upd.minblocksize_ = minblocksize_;

	auto blocks_left = hashed_blocks_;       // This will move into upd one by one.

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
	std::set<uint32_t, greater_pow2_prio> block_sizes; for(auto block : offset_blocks_){block_sizes.insert(block.second->enc_block_.blocksize_);}

	//
	std::list<empty_block_t> empty_blocks;  // contains empty_block_t's
	empty_blocks.push_back(empty_block_t(0, upd.size_));

	for(auto blocksize : block_sizes){
		for(auto empty_block_it = empty_blocks.begin(); empty_block_it != empty_blocks.end(); ){
			if(empty_block_it->second < blocksize) {empty_block_it++; continue;}

			offset_t offset = empty_block_it->first;
			std::vector<uint8_t> blockbuf = datafile.get(offset, blocksize);

			StatefulRsyncChecksum checksum(blockbuf.begin(), blockbuf.end());

			decltype(hashed_blocks_)::iterator matched_it;
			do {
				matched_it = match_block(blockbuf, blocks_left, checksum);
				if(matched_it != blocks_left.end()){
					upd.offset_blocks_.insert(std::make_pair(offset, matched_it->second));
					upd.hashed_blocks_.insert(std::make_pair(checksum, matched_it->second));
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
		log_unmatched(empty_block_it->first, empty_block_it->second);

		auto lb_block = upd.offset_blocks_.lower_bound(empty_block_it->first);
		std::shared_ptr<DecryptedBlock> left_blk, right_blk;
		if(lb_block != upd.offset_blocks_.end()){
			right_blk = lb_block->second;
		}
		if(lb_block != upd.offset_blocks_.begin()){
			--lb_block;
			left_blk = lb_block->second;
		}

		upd.create_neighbormap(datafile, left_blk, right_blk, *empty_block_it);
	}

	return upd;
}

DecryptedBlock FileMap::process_block(const std::vector<uint8_t>& data) {
	CryptoPP::AutoSeededRandomPool rng;

	DecryptedBlock block;
	block.enc_block_.blocksize_ = (uint32_t)data.size();

	block.enc_block_.iv_.resize(16);
	rng.GenerateBlock(block.enc_block_.iv_.data(), 16);

	block.enc_block_.encrypted_data_hash_ = compute_strong_hash( encrypt_block(data, key_, block.enc_block_.iv_) , strong_hash_type_);

	block.strong_hash_ = compute_strong_hash(data, strong_hash_type_);
	block.weak_hash_ = RsyncChecksum(data.begin(), data.end());

	block.encrypt_hashes(key_);

	return block;
}

decltype(FileMap::hashed_blocks_)::iterator FileMap::match_block(const blob& datablock, decltype(hashed_blocks_)& blockset, weakhash_t checksum) {
	auto eqhash_blocks = blockset.equal_range(checksum);
	blob strong_hash = compute_strong_hash(datablock, strong_hash_type_);

	if(eqhash_blocks != std::make_pair(blockset.end(), blockset.end())){
		for(auto eqhash_block = eqhash_blocks.first; eqhash_block != eqhash_blocks.second; eqhash_block++){
			if(strong_hash == eqhash_block->second->strong_hash_){
				log_matched(checksum, datablock.size());
				return eqhash_block;
			}
		}
	}
	return hashed_blocks_.end();
}

void FileMap::set_blocks(const std::vector<Block>& new_blocks) {
	EncFileMap::set_blocks(new_blocks);
	hashed_blocks_.clear();
	for(auto block : offset_blocks_){
		block.second->decrypt_hashes(key_);
		hashed_blocks_.insert(std::make_pair(block.second->weak_hash_, block.second));
	}
}

std::shared_ptr<DecryptedBlock> FileMap::create_block(File& datafile, empty_block_t unassigned_space, int num){
	std::shared_ptr<DecryptedBlock> processed_block = std::make_shared<DecryptedBlock>(process_block(datafile.get(unassigned_space.first, unassigned_space.second)));

	print_debug_block(*processed_block, num);

	hashed_blocks_.insert({processed_block->weak_hash_, processed_block});	// TODO: We have a great race condition here. MUST BE FIXED!
	offset_blocks_.insert({unassigned_space.first, processed_block});	// TODO: Also here. Protect hashed_blocks, offset_blocks!
	return processed_block;
}

void FileMap::create_neighbormap(File& datafile,
		std::shared_ptr<DecryptedBlock> left, std::shared_ptr<DecryptedBlock> right,
		empty_block_t unassigned_space) {
	if(!right && !left){
		fill_with_map(datafile, unassigned_space);
	}else if(!right){	// Append in the end.
		if(left->enc_block_.blocksize_ < maxblocksize_){
			unassigned_space.first -= left->enc_block_.blocksize_;
			unassigned_space.second += left->enc_block_.blocksize_;
			hashed_blocks_.erase(left->weak_hash_);
			offset_blocks_.erase(unassigned_space.first);
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

#ifndef SINGLE_THREADED
	// Threaded initialization
	for(auto threadnum = 0; threadnum < (std::thread::hardware_concurrency() == 0 ? 0 : std::thread::hardware_concurrency()-1); threadnum++){
		threads.emplace_back(std::bind(static_cast<size_t (boost::asio::io_service::*) ()>(&boost::asio::io_service::run), &io_service));
	}
#endif // SINGLE_THREADED

	int block_count = 0;
	while(unassigned_space.second != 0){
		size_t bytes_to_read = std::min(unassigned_space.second, maxblocksize_);
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

void FileMap::log_matched(weakhash_t checksum, size_t size) {
	if(logger){
		std::ostringstream hex_checksum; hex_checksum << "0x" << std::hex << std::setfill('0') << std::setw(8) << checksum;
		logger->debug() << "Matched block: " << hex_checksum.str() << " size=" << size;
	}
}

void FileMap::log_unmatched(offset_t offset, uint32_t size) {
	if(logger){
		logger->debug() << "Unmatched block: off=" << offset << " size=" << size;
	}
}

} /* namespace internals */
} /* namespace librevault */
