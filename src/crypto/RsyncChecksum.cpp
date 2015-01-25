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
#include "RsyncChecksum.h"
#include <iostream>

RsyncChecksum::operator weakhash_t() const {
	return (s1 & 0xffff) | (s2 << 16);
}

weakhash_t RsyncChecksum::compute(const char* source, size_t len) {
	s1 = 0; s2 = 0; count = 0;
	for(auto i = len; i--; i != 0){
		s1 += (*reinterpret_cast<const unsigned char*>(source) + char_offset);
		s2 += s1;
		source++;
	}
	count += len;
	return static_cast<uint32_t>(*this);
}

weakhash_t RsyncChecksum::roll(uint8_t out, uint8_t in) {
	s1 -= (out+char_offset); s1 += (in+char_offset);
	s2 -= count*(out+char_offset); s2 += s1;
	return static_cast<uint32_t>(*this);
}
