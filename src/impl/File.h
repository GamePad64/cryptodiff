/* Copyright (C) 2015 Alexander Shishenko <GamePad64@gmail.com>
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
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <boost/noncopyable.hpp>

#define FORCE_FILE_BACKEND 1

#ifndef FORCE_FILE_BACKEND
#	if UINTPTR_MAX == 0xffffffffffffffff
#		define FILE_BACKEND 1	// boost::iostreams::mapped_file_source
#	elif UINTPTR_MAX == 0xffffffff
#		define FILE_BACKEND 2	// std::ifstream
#	endif
#else
#	define FILE_BACKEND FORCE_FILE_BACKEND
#endif

#if FILE_BACKEND == 1
#	include <boost/iostreams/device/mapped_file.hpp>
#elif FILE_BACKEND == 2
#	include <iostream>
#	include <fstream>
#	include <mutex>
#endif

namespace cryptodiff {
namespace internals {

#if FILE_BACKEND == 1

class File : boost::noncopyable {
public:
	File(const std::string& path) : mapped_file_(path) {}
	virtual ~File() {mapped_file_.close();}

	uint64_t size() {return mapped_file_.size();}
	std::vector<uint8_t> get(uint64_t offset, uint32_t size){
		const uint8_t* begin = reinterpret_cast<const uint8_t*>(mapped_file_.data())+offset;
		const uint8_t* end = begin+size;
		return std::vector<uint8_t>(begin, end);
	}
	uint8_t get(uint64_t offset) {
		return *(mapped_file_.data());
	}
private:
	boost::iostreams::mapped_file_source mapped_file_;
};

#elif FILE_BACKEND == 2

class File : boost::noncopyable {
public:
	File(const std::string& path) : ifs_(path, std::ios_base::in | std::ios_base::binary) {}
	virtual ~File() {}

	uint64_t size() {
		std::lock_guard<std::mutex> lk(mutex_);

		ifs_.seekg(0, ifs_.end);
		auto size = ifs_.tellg();

		return size;
	}
	std::vector<uint8_t> get(uint64_t offset, uint32_t size) {
		std::lock_guard<std::mutex> lk(mutex_);

		std::vector<uint8_t> rdbuf(size);
		ifs_.seekg(offset);
		ifs_.read(reinterpret_cast<char*>(rdbuf.data()), size);

		return rdbuf;
	}
	uint8_t get(uint64_t offset) {
		std::lock_guard<std::mutex> lk(mutex_);
		ifs_.seekg(offset);

		return ifs_.get();
	}
private:
	std::ifstream ifs_;
	std::mutex mutex_;
};

#endif

} /* namespace internals */
} /* namespace cryptodiff */
