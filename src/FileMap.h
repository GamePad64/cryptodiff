/*
 * FileMap.h
 *
 *  Created on: 04 февр. 2015 г.
 *      Author: gamepad
 */

#ifndef SRC_FILEMAP_H_
#define SRC_FILEMAP_H_

#include "EncFileMap.h"
#include <unordered_map>

class FileMap: public EncFileMap {
protected:
	using empty_block_t = std::pair<offset_t, uint32_t>;    // offset, length.

	std::unordered_multimap<weakhash_t, std::shared_ptr<Block>> hashed_blocks;

	Botan::SymmetricKey key;

	// Encrypt
	Block::Hashes decrypt_hashes(const std::array<uint8_t, sizeof(Block::Hashes)>& encrypted_hashes, const Botan::InitializationVector& iv, const Botan::SymmetricKey& key);
	std::array<uint8_t, sizeof(Block::Hashes)> encrypt_hashes(Block::Hashes decrypted_hashes, const Botan::InitializationVector& iv, const Botan::SymmetricKey& key);

	// Subroutines for creating block signature
	Block process_block(const uint8_t* data, size_t size){Botan::AutoSeeded_RNG rng; auto iv = rng.random_vec(AES_BLOCKSIZE); return process_block(data, size, iv);};
	Block process_block(const uint8_t* data, size_t size, const Botan::InitializationVector& iv);

	//
	void create_block();
	void fill_with_map(std::istream& datafile, empty_block_t unassigned_space);
	void fill_with_map(const uint8_t* data, size_t size, empty_block_t unassigned_space);

	void create_neighbormap(std::istream& datafile, std::shared_ptr<Block> left, std::shared_ptr<Block> right, empty_block_t unassigned_space);

	// Subroutine for matching blockbuf with defined checksum and existing block signature from blockset.
	decltype(hashed_blocks)::iterator match_block(const uint8_t* data, size_t size, decltype(hashed_blocks)& blockset, RsyncChecksum checksum);
public:
	FileMap(const Botan::SymmetricKey& key);
	virtual ~FileMap();

	void create(std::istream& datafile, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	void create_mt(std::istream& datafile, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	void create_mmap(const uint8_t* mmaped, size_t size, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	void create_mmap_mt(const uint8_t* mmaped, size_t size, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);

	FileMap update(std::istream& datafile);

	virtual void from_file(std::istream& lvfile);

	virtual void print_debug_block(const Block& block, int count = 0) const;
};

#endif /* SRC_FILEMAP_H_ */
