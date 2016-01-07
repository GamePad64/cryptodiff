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
#include "EncFileMap.h"

namespace cryptodiff {
namespace internals {

std::shared_ptr<spdlog::logger> logger = std::shared_ptr<spdlog::logger>();
boost::asio::io_service* io_service_ptr = new boost::asio::io_service();
bool internal_ios = true;
std::unique_ptr<boost::asio::io_service::work> io_service_work = std::make_unique<boost::asio::io_service::work>(*io_service_ptr);
std::thread io_service_thread = std::thread(std::bind((size_t(boost::asio::io_service::*)())&boost::asio::io_service::run, io_service_ptr));

void DecryptedBlock::encrypt_hashes(const blob& key){
	struct Hashes {
		uint32_t weak_hash;
		std::array<uint8_t, 28> strong_hash;
	} temp_hashes;
	temp_hashes.weak_hash = boost::endian::native_to_big(weak_hash_);
	std::copy(strong_hash_.begin(), strong_hash_.begin()+std::min(strong_hash_.size(), (size_t)28), temp_hashes.strong_hash.begin());

	enc_block_.encrypted_rsync_hashes_ = blob((uint8_t*)&temp_hashes, (uint8_t*)&temp_hashes+sizeof(Hashes)) |
			crypto::AES_CBC(key, enc_block_.iv_, false);
}

void DecryptedBlock::decrypt_hashes(const blob& key){
	auto decrypted_vector = enc_block_.encrypted_rsync_hashes_ | crypto::De<crypto::AES_CBC>(key, enc_block_.iv_, false);

	struct Hashes {
		uint32_t weak_hash;
		std::array<uint8_t, 28> strong_hash;
	} temp_hashes;
	std::move(decrypted_vector.begin(), decrypted_vector.end(), (uint8_t*)&temp_hashes);

	weak_hash_ = boost::endian::big_to_native(temp_hashes.weak_hash);
	strong_hash_.resize(temp_hashes.strong_hash.size());
	std::copy(temp_hashes.strong_hash.begin(), temp_hashes.strong_hash.end(), strong_hash_.begin());
}

std::string DecryptedBlock::debug_string() const {
	std::ostringstream debug_string_os;

	// Found in encrypted
	auto encrypted_data_hash_hex = enc_block_.encrypted_data_hash_ | crypto::Hex();
	auto iv_hex = enc_block_.iv_ | crypto::Hex();
	auto encrypted_rsync_hashes_hex = enc_block_.encrypted_rsync_hashes_ | crypto::Hex();

	debug_string_os << " Size=" << enc_block_.blocksize_
					<< " Hash(data)=" << std::string(std::make_move_iterator(encrypted_data_hash_hex.begin()), std::make_move_iterator(encrypted_data_hash_hex.end()))
					<< " IV=" << std::string(std::make_move_iterator(iv_hex.begin()), std::make_move_iterator(iv_hex.end()))
					<< " AES(Rsync(Block))=" << std::string(std::make_move_iterator(encrypted_rsync_hashes_hex.begin()), std::make_move_iterator(encrypted_rsync_hashes_hex.end()));
	if(strong_hash_.empty()){
		// Found in unencrypted
		std::ostringstream hex_checksum; hex_checksum << "0x" << std::hex << std::setfill('0') << std::setw(8) << weak_hash_;
		auto strong_hash_hex = strong_hash_ | crypto::Hex();

		debug_string_os << " Rsync(DecryptedBlock)=" << hex_checksum.str()
						<< " Hash(DecryptedBlock)=" << std::string(std::make_move_iterator(strong_hash_hex.begin()), std::make_move_iterator(strong_hash_hex.end()));
	}
	return debug_string_os.str();
}

EncFileMap::EncFileMap() {}
EncFileMap::~EncFileMap() {}

std::vector<Block> EncFileMap::blocks() const {
	std::vector<Block> blist;
	for(auto block : offset_blocks_){
		blist.push_back(block.second->enc_block_);
	}
	return blist;
}

std::vector<Block> EncFileMap::delta(const EncFileMap& old_filemap){
	auto strong_hash_less = [](const decltype(offset_blocks_ | boost::adaptors::map_values)::value_type &block1, const decltype(offset_blocks_ | boost::adaptors::map_values)::value_type &block2){
		return block1->enc_block_.encrypted_data_hash_ < block2->enc_block_.encrypted_data_hash_;
	};

	std::list<std::shared_ptr<const DecryptedBlock>> missing_blocks;
	std::set_difference(
			(offset_blocks_ | boost::adaptors::map_values).begin(),
			(offset_blocks_ | boost::adaptors::map_values).end(),
			(old_filemap.offset_blocks_ | boost::adaptors::map_values).begin(),
			(old_filemap.offset_blocks_ | boost::adaptors::map_values).end(),
			std::back_inserter(missing_blocks), strong_hash_less);

	std::vector<Block> blist;
	for(auto block_ptr : missing_blocks){
		blist.push_back(block_ptr->enc_block_);
	}
	return blist;
}

std::string EncFileMap::debug_string() const {
	std::ostringstream os;
	int i = 0;
	for(auto block : offset_blocks_){
		os << "N=" << ++i << " " <<  block.second->debug_string();
		print_debug_block(*(block.second), ++i);
	}
	return os.str();
}

void EncFileMap::print_debug_block(const DecryptedBlock& block, int num) const {
	if(logger){
		logger->debug() << "N=" << num << " " << block.debug_string();
	}
}

void EncFileMap::set_blocks(const std::vector<Block>& new_blocks) {
	size_ = 0;
	offset_blocks_.clear();
	for(auto block : new_blocks){
		auto new_block = std::make_shared<DecryptedBlock>();
		new_block->enc_block_ = block;

		offset_blocks_.insert(make_pair(size_, new_block));
		size_ += block.blocksize_;
	}
}

} /* namespace internals */
} /* namespace librevault */
