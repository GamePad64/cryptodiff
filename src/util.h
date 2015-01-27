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

#include <sstream>
#include <iomanip>
#include <cstdint>
#include <iostream>
#include <string>

uint64_t filesize(std::istream& ifile){
	auto cur_pos = ifile.tellg();
	ifile.seekg(0, ifile.end);
	auto size = ifile.tellg();
	ifile.seekg(cur_pos);
	return size;
}

uint64_t filesize(std::ostream& ofile){
	auto cur_pos = ofile.tellp();
	ofile.seekp(0, ofile.end);
	auto size = ofile.tellp();
	ofile.seekp(cur_pos);
	return size;
}

std::string encrypt(const std::string& data, Botan::SymmetricKey key, Botan::InitializationVector iv, bool nopad = false) {
	Botan::Pipe pipe(get_cipher(nopad ? "AES-256/CBC/NoPadding" : "AES-256/CBC", Botan::OctetString(key), Botan::OctetString(iv), Botan::ENCRYPTION));
	pipe.process_msg(data);

	return pipe.read_all_as_string(0);
}

std::string to_hex(const std::string& s)
{
    std::ostringstream ret;

    for (std::string::size_type i = 0; i < s.length(); ++i)
        ret << std::hex << std::setfill('0') << std::setw(2) << (int)s[i];

    return ret.str();
}

std::string to_hex(const uint32_t& s){
	std::ostringstream ret;
	ret << "0x" << std::hex << std::setfill('0') << std::setw(8) << s;

	return ret.str();
}

#endif /* SRC_UTIL_H_ */
