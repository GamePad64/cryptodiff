/*
 * fs.h
 *
 *  Created on: 24 янв. 2015 г.
 *      Author: gamepad
 */

#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

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

#endif /* SRC_UTIL_H_ */
