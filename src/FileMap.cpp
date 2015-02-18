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
#include "impl/EncFileMap.h"
#include "impl/FileMap.h"

namespace filemap {

/* Block */
Block::Block(){
	pImpl = new internals::Block();
}
Block::Block(const Block& block){
	pImpl = new internals::Block(*reinterpret_cast<internals::Block*>(pImpl));
}
Block::Block(Block&& block){
	std::swap(pImpl, block.pImpl);
}
Block& Block::operator=(const Block& block){
	delete reinterpret_cast<internals::Block*>(pImpl);
	pImpl = new internals::Block(*reinterpret_cast<internals::Block*>(pImpl));
	return *this;
}
Block& Block::operator=(Block&& block){
	std::swap(pImpl, block.pImpl);
	return *this;
}
Block::~Block(){
	delete reinterpret_cast<internals::Block*>(pImpl);
}

const std::array<uint8_t, SHASH_LENGTH>& Block::get_encrypted_hash() const {
	return reinterpret_cast<internals::Block*>(pImpl)->encrypted_hash;
}
void Block::set_encrypted_hash(const std::array<uint8_t, SHASH_LENGTH>& encrypted_hash){
	reinterpret_cast<internals::Block*>(pImpl)->encrypted_hash = encrypted_hash;
}

uint32_t Block::get_blocksize() const {
	return reinterpret_cast<internals::Block*>(pImpl)->blocksize;
}
void Block::set_blocksize(uint32_t blocksize) {
	reinterpret_cast<internals::Block*>(pImpl)->blocksize = blocksize;
}

const std::array<uint8_t, AES_BLOCKSIZE>& Block::get_iv() const {
	return reinterpret_cast<internals::Block*>(pImpl)->iv;
}
void Block::set_iv(const std::array<uint8_t, AES_BLOCKSIZE>& iv) {
	reinterpret_cast<internals::Block*>(pImpl)->iv = iv;
}

uint32_t Block::get_decrypted_weak_hash() const {
	return reinterpret_cast<internals::Block*>(pImpl)->decrypted_hashes_part.weak_hash;
}
void Block::set_decrypted_weak_hash(uint32_t decrypted_weak_hash) {
	reinterpret_cast<internals::Block*>(pImpl)->decrypted_hashes_part.weak_hash = decrypted_weak_hash;
}
const std::array<uint8_t, SHASH_LENGTH>& Block::get_decrypted_strong_hash() const {
	return reinterpret_cast<internals::Block*>(pImpl)->decrypted_hashes_part.strong_hash;
}
void Block::set_decrypted_strong_hash(const std::array<uint8_t, SHASH_LENGTH>& decrypted_strong_hash) {
	reinterpret_cast<internals::Block*>(pImpl)->decrypted_hashes_part.strong_hash = decrypted_strong_hash;
}

const std::array<uint8_t, sizeof(Block::Hashes)>& Block::get_encrypted_hashes_part() const {
	return reinterpret_cast<internals::Block*>(pImpl)->encrypted_hashes_part;
}
void Block::set_encrypted_hashes_part(const std::array<uint8_t, sizeof(Hashes)>& encrypted_hashes_part) {
	reinterpret_cast<internals::Block*>(pImpl)->encrypted_hashes_part = encrypted_hashes_part;
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

std::vector<Block> EncFileMap::delta(const EncFileMap& old_filemap){
	auto delta_ptrlist = reinterpret_cast<internals::EncFileMap*>(pImpl)->delta(*reinterpret_cast<internals::EncFileMap*>(old_filemap.pImpl));
	std::vector<Block> delta_vec; delta_vec.reserve(delta_ptrlist.size());
	for(auto block_ptr : delta_ptrlist){
		Block b; *reinterpret_cast<internals::Block*>(b.get_implementation()) = *block_ptr.get();
		delta_vec.push_back(b);
	}
	return delta_vec;
}

void EncFileMap::from_file(std::istream& lvfile){
	reinterpret_cast<internals::EncFileMap*>(pImpl)->from_file(lvfile);
}
void EncFileMap::to_file(std::ostream& lvfile){
	reinterpret_cast<internals::EncFileMap*>(pImpl)->to_file(lvfile);
}

void EncFileMap::print_debug() const {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->print_debug();
}
void EncFileMap::print_debug_block(const Block& block, int count) const {
	reinterpret_cast<internals::EncFileMap*>(pImpl)->print_debug_block(*reinterpret_cast<const internals::Block*>(const_cast<Block&>(block).get_implementation()), count);
}

uint32_t EncFileMap::get_maxblocksize() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->get_maxblocksize();
}
uint32_t EncFileMap::get_minblocksize() const {
	return reinterpret_cast<internals::EncFileMap*>(pImpl)->get_minblocksize();
}

/* FileMap */
FileMap::FileMap(){pImpl = nullptr;}
FileMap::FileMap(const std::array<uint8_t, AES_KEYSIZE>& key){
	pImpl = new internals::FileMap(key);
}
FileMap::~FileMap(){}

void FileMap::create(std::istream& datafile, uint32_t maxblocksize, uint32_t minblocksize){
	reinterpret_cast<internals::FileMap*>(pImpl)->create(datafile, maxblocksize, minblocksize);
}
FileMap FileMap::update(std::istream& datafile){
	FileMap new_map;
	auto new_internal = new internals::FileMap(reinterpret_cast<internals::FileMap*>(pImpl)->update(datafile));
	std::swap(*reinterpret_cast<internals::FileMap*>(pImpl), *new_internal);
	delete new_internal;
	return new_map;
}

} /* namespace librevault */
