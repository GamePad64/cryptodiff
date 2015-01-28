/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once

#include <cstdint>
#include <string>

using weakhash_t = uint32_t;

class RsyncChecksum {
	const uint8_t char_offset = 31;
	size_t count = 0;
	weakhash_t s1 = 0, s2 = 0;
public:
	RsyncChecksum(){}
	RsyncChecksum(const char* source, size_t len) : RsyncChecksum(){compute(source, len);}
	RsyncChecksum(const std::string& source) : RsyncChecksum(){compute(source);};
	template<class InputIterator> RsyncChecksum(InputIterator first, InputIterator last) : RsyncChecksum(){compute(first, last);};

	operator weakhash_t() const {return (s1 & 0xffff) | (s2 << 16);}

	/**
	 * Computation itself. Based on work of Donovan Baarda <abo@minkirri.apana.org.au>. Code modified from librsync.
	 * @param source
	 * @param len
	 * @return
	 */
	template<class InputIterator> weakhash_t compute(InputIterator first, InputIterator last){
		s1 = 0; s2 = 0; count = 0;
		for(auto it = first; it != last; it++){
			s1 += (*reinterpret_cast<const unsigned char*>(&*first) + char_offset);
			s2 += s1;
			count++;
		}
		return static_cast<uint32_t>(*this);
	}
	weakhash_t compute(const char* source, size_t len);
	weakhash_t compute(const std::string& source){return compute(source.data(), (size_t)source.size());}

	weakhash_t roll(uint8_t out, uint8_t in){
		s1 -= (out+char_offset); s1 += (in+char_offset);
		s2 -= count*(out+char_offset); s2 += s1;
		return static_cast<uint32_t>(*this);
	}
};
