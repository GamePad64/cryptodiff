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
#include "impl/EncFileMap.h"
#include "impl/FileMap.h"

namespace cryptodiff {

void set_logger(std::shared_ptr<spdlog::logger> logger) {
	internals::set_logger(logger);
}

void set_io_service(std::shared_ptr<boost::asio::io_service> io_service_ptr) {
	internals::set_io_service(io_service_ptr);
}

std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& datablock, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
	return datablock | crypto::AES_CBC(key, iv, datablock.size() % 16 != 0);
}

std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& datablock, uint32_t blocksize, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
	return datablock | crypto::De<crypto::AES_CBC>(key, iv, blocksize % 16 != 0);
}

std::vector<uint8_t> compute_strong_hash(const std::vector<uint8_t>& data, StrongHashType type) {
	switch(type){
		case SHA3_224: return data | crypto::SHA3(224);
		case SHA2_224: return data | crypto::SHA2(224);
		default: return std::vector<uint8_t>();	// TODO: throw some exception.
	}
}

/* EncFileMap */
EncFileMap::EncFileMap(){
	pImpl = new internals::EncFileMap();
}
EncFileMap::EncFileMap(const EncFileMap& encfilemap){
	pImpl = new internals::EncFileMap(*reinterpret_cast<internals::EncFileMap*>(encfilemap.pImpl));
}
EncFileMap::EncFileMap(EncFileMap&& encfilemap){
	std::swap(pImpl, encfilemap.pImpl);
}
EncFileMap& EncFileMap::operator=(const EncFileMap& encfilemap){
	delete reinterpret_cast<internals::EncFileMap*>(pImpl);
	pImpl = new internals::EncFileMap(*reinterpret_cast<internals::EncFileMap*>(pImpl));
	return *this;
}
EncFileMap& EncFileMap::operator=(EncFileMap&& encfilemap){
	std::swap(pImpl, encfilemap.pImpl);
	return *this;
}
EncFileMap::~EncFileMap(){
	delete reinterpret_cast<internals::EncFileMap*>(pImpl);
}

std::vector<Block> EncFileMap::delta(const EncFileMap& old_filemap) {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->delta(*reinterpret_cast<internals::EncFileMap*>(old_filemap.pImpl));
}

/* Debug */
std::string EncFileMap::debug_string() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->debug_string();
}

/* Getters */
std::vector<Block> EncFileMap::blocks() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->blocks();
}
uint32_t EncFileMap::maxblocksize() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->maxblocksize();
}
uint32_t EncFileMap::minblocksize() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->minblocksize();
}
uint64_t EncFileMap::filesize() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->filesize();
}
StrongHashType EncFileMap::strong_hash_type() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->strong_hash_type();
}
WeakHashType EncFileMap::weak_hash_type() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->weak_hash_type();
}

/* Setters */
void EncFileMap::set_blocks(const std::vector<Block>& new_blocks) {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->set_blocks(new_blocks);
}
void EncFileMap::set_maxblocksize(uint32_t new_maxblocksize) {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->set_maxblocksize(new_maxblocksize);
}
void EncFileMap::set_minblocksize(uint32_t new_minblocksize) {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->set_minblocksize(new_minblocksize);
}
void EncFileMap::set_strong_hash_type(StrongHashType new_strong_hash_type) {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->set_strong_hash_type(new_strong_hash_type);
}
void EncFileMap::set_weak_hash_type(WeakHashType new_weak_hash_type) {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->set_weak_hash_type(new_weak_hash_type);
}

/* FileMap */
FileMap::FileMap() {
	pImpl = nullptr;
}

FileMap::FileMap(std::vector<uint8_t> key) {
	pImpl = new internals::FileMap(std::move(key));
}
FileMap::~FileMap(){}

void FileMap::create(const std::string& datafile) {
	reinterpret_cast<internals::FileMap*>(pImpl)->create(datafile);
}
FileMap FileMap::update(const std::string& datafile) {
	FileMap new_map;
	auto new_internal = new internals::FileMap(reinterpret_cast<internals::FileMap*>(pImpl)->update(datafile));
	std::swap(*reinterpret_cast<internals::FileMap*>(pImpl), *new_internal);
	delete new_internal;
	return new_map;
}

} /* namespace librevault */
