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
	if(maxblocksize_ == 0) throw error("Maximum block size must be > 0");

	File datafile(path);

	FileMap upd(key_); upd.size_ = datafile.size();
	upd.maxblocksize_ = maxblocksize_;
	upd.minblocksize_ = minblocksize_;
	upd.strong_hash_type_ = strong_hash_type_;
	upd.weak_hash_type_ = weak_hash_type_;

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

	AvailabilityMap<offset_t> av_map(upd.size_);

	// Step 1: Try to match file to blocks we have. Block is matched by weakhash, and then by stronghash
	for(auto blocksize : block_sizes){
		for(auto empty_block_it = av_map.begin(); empty_block_it != av_map.end(); ){
			if(empty_block_it->second < blocksize) {empty_block_it++; continue;}

			const offset_t orig_offset = empty_block_it->first;

			// Reading to block buffer
			std::vector<uint8_t> tmp_blockbuf = datafile.get(orig_offset, blocksize);
			StatefulRsyncChecksum checksum(tmp_blockbuf.begin(), tmp_blockbuf.end());
			tmp_blockbuf.clear();

			bool incremented_empty_block_it = false;
			for(offset_t current_offset = orig_offset; current_offset+blocksize < orig_offset+empty_block_it->second; current_offset++) {
				auto matched_it = match_block(checksum, blocks_left);
				if(matched_it != blocks_left.end()) {   // Block matched successfully
					log_matched(checksum, blocksize);

					empty_block_it = av_map.insert({current_offset, blocksize}).first;
					incremented_empty_block_it = true;
					blocks_left.erase(matched_it);
					break;
				}
				checksum.roll(datafile.get(++current_offset));
			}
			if(!incremented_empty_block_it) empty_block_it++;
		}
	}

	// Step 2: Unmatched blocks will be added to filemap
	for(auto empty_block : av_map){
		log_unmatched(empty_block.first, empty_block.second);

		auto lb_block = upd.offset_blocks_.lower_bound(empty_block.first);
		std::shared_ptr<DecryptedBlock> left_blk, right_blk;
		if(lb_block != upd.offset_blocks_.end())    right_blk = lb_block->second;
		if(lb_block != upd.offset_blocks_.begin())  left_blk = (--lb_block)->second;

		upd.create_neighbormap(datafile, left_blk, right_blk, empty_block);
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

FileMap::weakhash_map::iterator FileMap::match_block(const StatefulRsyncChecksum& checksum, weakhash_map& blockset) {
	auto eqhash_blocks = blockset.equal_range(checksum);

	if(eqhash_blocks.first != eqhash_blocks.second){
		blob datablock = blob(checksum.state_buffer().begin(), checksum.state_buffer().end());
		blob strong_hash = compute_strong_hash(datablock, strong_hash_type_);
		for(auto eqhash_block = eqhash_blocks.first; eqhash_block != eqhash_blocks.second; eqhash_block++){
			if(strong_hash == eqhash_block->second->strong_hash_){
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

std::shared_ptr<DecryptedBlock> FileMap::create_block(File& datafile, block_type unassigned_space, int num){
	std::shared_ptr<DecryptedBlock> processed_block = std::make_shared<DecryptedBlock>(process_block(datafile.get(unassigned_space.first, unassigned_space.second)));

	print_debug_block(*processed_block, num);

	hashed_blocks_.insert({processed_block->weak_hash_, processed_block});	// TODO: We have a great race condition here. MUST BE FIXED!
	offset_blocks_.insert({unassigned_space.first, processed_block});	// TODO: Also here. Protect hashed_blocks, offset_blocks!
	return processed_block;
}

void FileMap::create_neighbormap(File& datafile,
		std::shared_ptr<DecryptedBlock> left, std::shared_ptr<DecryptedBlock> right,
		block_type unassigned_space) {
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

void FileMap::fill_with_map(File& datafile, block_type unassigned_space) {
	if(unassigned_space.second == 0) return;

	boost::asio::io_service io_service;
	auto work = new boost::asio::io_service::work(io_service);

	std::vector<std::thread> threads;

#ifndef SINGLE_THREADED
	// Threaded initialization
	for(unsigned int threadnum = 0; threadnum < (std::thread::hardware_concurrency() == 0 ? 0 : std::thread::hardware_concurrency()-1); threadnum++){
		threads.emplace_back(std::bind(static_cast<size_t (boost::asio::io_service::*) ()>(&boost::asio::io_service::run), &io_service));
	}
#endif // SINGLE_THREADED

	int block_count = 0;
	while(unassigned_space.second != 0){
		size_t bytes_to_read = std::min(unassigned_space.second, (uint64_t)maxblocksize_);
		io_service.post(std::bind(&FileMap::create_block, this, std::ref(datafile), block_type{unassigned_space.first, bytes_to_read}, ++block_count));
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
