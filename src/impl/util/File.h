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
#include <iostream>
#include <fstream>
#include <mutex>
#include <boost/noncopyable.hpp>

namespace cryptodiff {
namespace internals {

class File : boost::noncopyable {
public:
	File(const std::string& path) : path_(path) {
		ifs_.exceptions(std::ios::failbit | std::ios::badbit);
		ifs_.open(path, std::ios_base::in | std::ios_base::binary);
	}
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
	const std::string path_;
	std::ifstream ifs_;
	std::mutex mutex_;
};

} /* namespace internals */
} /* namespace cryptodiff */
