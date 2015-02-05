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
	std::unordered_multimap<weakhash_t, std::shared_ptr<Block>> hashed_blocks;

	Botan::SymmetricKey key;

	// Subroutines for creating block signature
	Block process_block(const std::string& binblock){Botan::AutoSeeded_RNG rng; auto iv = rng.random_vec(AES_BLOCKSIZE); return process_block(binblock, iv);};
	Block process_block(const std::string& binblock, const Botan::InitializationVector& iv);

	// Subroutine for matching blockbuf with defined checksum and existing block signature from blockset.
	decltype(hashed_blocks)::iterator match_block(decltype(hashed_blocks)& blockset, const std::string& blockbuf, RsyncChecksum checksum);
public:
	FileMap(const Botan::SymmetricKey& key);
	virtual ~FileMap();

	void create(std::istream& datafile, uint32_t maxblocksize = 2*1024*1024, uint32_t minblocksize = 32 * 1024);
	FileMap update(std::istream& datafile);

	virtual void print_debug() const;
};

#endif /* SRC_FILEMAP_H_ */
