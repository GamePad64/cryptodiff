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

#include <cstdint>
#include <string>

using weakhash_t = uint32_t;

class RsyncChecksum {
	const uint8_t char_offset = 31;
	uint_fast32_t count = 0;
	uint_fast32_t s1 = 0, s2 = 0;
public:
	RsyncChecksum(){}
	template<class InputIterator> RsyncChecksum(InputIterator first, InputIterator last) : RsyncChecksum(){compute(first, last);}

	operator weakhash_t() const {return (s1 & 0xffff) | (s2 << 16);}

	/**
	 * Computation itself. Based on work of Donovan Baarda <abo@minkirri.apana.org.au>. Code modified from librsync.
	 * @param first
	 * @param last
	 * @return
	 */
	template<class InputIterator> weakhash_t compute(InputIterator first, InputIterator last){
		s1 = 0; s2 = 0;
		count = std::distance(first, last);
		for(auto it = first; it != last; it++){
			s1 += (reinterpret_cast<const uint8_t&>(*it) + char_offset);
			s2 += s1;
		}
		return static_cast<uint32_t>(*this);
	}

	weakhash_t roll(uint8_t out, uint8_t in){
		s1 -= (out+char_offset); s1 += (in+char_offset);
		s2 -= count*(out+char_offset); s2 += s1;
		return static_cast<uint32_t>(*this);
	}
};
