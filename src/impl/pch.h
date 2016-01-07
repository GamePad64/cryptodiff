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
#pragma once

// LVCrypto
#include <lvcrypto/HMAC-SHA3.h>
#include <lvcrypto/SHA3.h>
#include <lvcrypto/SHA2.h>
#include <lvcrypto/Base64.h>
#include <lvcrypto/Base32.h>
#include <lvcrypto/Hex.h>
#include <lvcrypto/AES_CBC.h>

// Crypto++
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>

// Boost
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <boost/asio.hpp>

#include <boost/endian/arithmetic.hpp>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <boost/lexical_cast.hpp>

#include <boost/predef.h>
#include <boost/range/adaptor/map.hpp>

// spdlog
#include <spdlog/spdlog.h>

// Standard C++ Libraries
#include <array>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace cryptodiff {
namespace internals {

namespace fs = boost::filesystem;

using boost::asio::io_service;

using byte = uint8_t;
using blob = std::vector<byte>;

} /* namespace internals */
} /* namespace cryptodiff */
