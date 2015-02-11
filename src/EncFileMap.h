/*
 * EncFileMap.h
 *
 *  Created on: 04 февр. 2015 г.
 *      Author: gamepad
 */

#ifndef SRC_ENCFILEMAP_H_
#define SRC_ENCFILEMAP_H_

#include "util.h"
#include "crypto/RsyncChecksum.h"
#include <string>
#include <map>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>

constexpr size_t AES_BLOCKSIZE = 16;
constexpr size_t AES_KEYSIZE = 32;
/*
struct Header {
	const std::array<char, 4> magic = {'L', 'V', 'S', '\n'};
	uint32_t maxblocksize;
	uint32_t minblocksize;
};	// 12 bytes
struct Chunk {
	struct Meta {
		std::array<char, SHASH_LENGTH> encrypted_hash;	// 28 bytes
		uint32_t blocksize;	// 4 bytes
		std::array<char, AES_BLOCKSIZE> iv;	// 16 bytes
	} meta;	// 48 bytes
	struct Encrypted {
		weakhash_t weak_hash;	// 4 bytes
		std::array<char, SHASH_LENGTH> strong_hash;	// 28 bytes
	} encrypted;	// 32 bytes = 2 AES blocks without padding
};	// 80 bytes.
*/

struct Block {
	std::array<uint8_t, SHASH_LENGTH> encrypted_hash;	// 28 bytes
	uint32_t blocksize;	// 4 bytes
	std::array<uint8_t, AES_BLOCKSIZE> iv;	// 16 bytes

	struct Hashes {
		weakhash_t weak_hash;	// 4 bytes
		std::array<uint8_t, SHASH_LENGTH> strong_hash;	// 28 bytes
	};
	std::array<uint8_t, sizeof(Hashes)> encrypted_hashes_part;
	Hashes decrypted_hashes_part;
};

class EncFileMap {
protected:
	using offset_t = uint64_t;

	// Map data
	uint32_t maxblocksize = 0;
	uint32_t minblocksize = 0;

	// Other data
	std::map<offset_t, std::shared_ptr<Block>> offset_blocks;
	offset_t size = 0;
public:
	EncFileMap();
	virtual ~EncFileMap();

	virtual void from_file(std::istream& lvfile);
	void to_file(std::ostream& lvfile);

	void print_debug() const;
	virtual void print_debug_block(const Block& block, int count = 0) const;
};

#endif /* SRC_ENCFILEMAP_H_ */
