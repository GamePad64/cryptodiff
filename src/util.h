/*
 * fs.h
 *
 *  Created on: 24 янв. 2015 г.
 *      Author: gamepad
 */

#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

#include <botan/botan.h>
#include <botan/keccak.h>
#include <botan/aes.h>

#include <boost/algorithm/string.hpp>

#include <sstream>
#include <iomanip>
#include <cstdint>
#include <iostream>
#include <string>

constexpr size_t SHASH_LENGTH = 28;

inline uint64_t filesize(std::istream& ifile){
	auto cur_pos = ifile.tellg();
	ifile.seekg(0, ifile.end);
	auto size = ifile.tellg();
	ifile.seekg(cur_pos);
	return size;
}

inline uint64_t filesize(std::ostream& ofile){
	auto cur_pos = ofile.tellp();
	ofile.seekp(0, ofile.end);
	auto size = ofile.tellp();
	ofile.seekp(cur_pos);
	return size;
}

inline std::string encrypt(const std::string& data, Botan::SymmetricKey key, Botan::InitializationVector iv, bool nopad = false) {
	Botan::Pipe pipe(get_cipher(nopad ? "AES-256/CBC/NoPadding" : "AES-256/CBC", key, iv, Botan::ENCRYPTION));
	pipe.process_msg(data);

	return pipe.read_all_as_string(0);
}

inline std::string decrypt(const std::string& data, Botan::SymmetricKey key, Botan::InitializationVector iv, bool nopad = false) {
	Botan::Pipe pipe(get_cipher(nopad ? "AES-256/CBC/NoPadding" : "AES-256/CBC", key, iv, Botan::DECRYPTION));
	pipe.process_msg(data);

	return pipe.read_all_as_string(0);
}

inline std::string to_hex(const std::string& s){
	Botan::Pipe pipe(new Botan::Hex_Encoder);
	pipe.process_msg(s);

	std::string hexdata(pipe.read_all_as_string(0));
	boost::algorithm::to_lower(hexdata);

	return hexdata;
}

inline std::string to_hex(const uint32_t& s){
	std::ostringstream ret;
	ret << "0x" << std::hex << std::setfill('0') << std::setw(8) << s;

	return ret.str();
}

inline std::array<char, SHASH_LENGTH> compute_shash(const char* data, size_t length) {
	Botan::Keccak_1600 hasher(SHASH_LENGTH*8);

	auto hash = hasher.process(reinterpret_cast<const uint8_t*>(data), length);
	std::array<char, SHASH_LENGTH> hash_array; memcpy((void*)&hash_array, hash.data(), SHASH_LENGTH);
	return hash_array;
}

#endif /* SRC_UTIL_H_ */
